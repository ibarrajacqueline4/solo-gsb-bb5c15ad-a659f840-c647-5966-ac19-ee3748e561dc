"""许可证策略判定（POST /license-policy）。

调用本模块前，请求的 ``current_lock`` 已由 :func:`app.audit.audit_lock`
判定为**有效**（无 missing / unavailable / constraint_mismatch /
extraneous）。因此与 :mod:`app.sbom` 一样，这里不做任何版本选择与约束
核对，只沿**已激活依赖图**（与 /dependency-paths 同一张图：按锁定版本、
目标环境下 marker 求值后激活的依赖）逐包判定许可证策略，并复用
:func:`app.paths.shortest_paths` 为每个命中的包附上根包到它的全部最短
包路径。

对每个可达包取其**锁定版本**候选携带的 ``metadata.license``：

* 未提供（``null`` / 空串）：整包判定为 ``unknown``（无法按表达式求值，
  但不阻断请求）；
* 提供文本：按 SPDX AND/OR/括号表达式解析（非法表达式抛
  LicenseExpressionError，API 层映射为 422），再用 allow/deny 两个标识
  集合做三态判定——拒绝进入 ``violations``，未知进入 ``unknowns``，
  允许不出现在结果中。

两个输出列表各自只取决于快照、目标环境、锁定清单与策略集合，均按
规范化包名排序；每条附 ``paths``（根包到该包的全部最短路径，字典序
排序，语义与 /dependency-paths 一致）。

判定严格分为**两个先后阶段**，错误响应优先级因此确定：

1. 先对**所有可达包**（按包名稳定顺序）完成 SPDX 解析与三态判定——
   本阶段不做任何路径查询、不触碰路径预算；任一表达式非法即按包名
   顺序命中首个非法包并抛 LicenseExpressionError（API 层映射为
   422）。因此只要存在非法表达式，结果稳定为 422，与包名及输入顺序
   无关，不会因前序包耗尽路径额度而被 409 抢先返回。
2. 全部表达式合法后，才为 violations/unknowns 的命中包查询最短路径。
   一次请求中**所有命中包待返回的最短路径共享同一个请求级预算**
   （app.paths.PATH_COUNT_LIMIT，1000 条）：命中包按包名顺序逐个查询
   路径并累计条数（violations 与 unknowns 合在同一条名字序上累计），
   加入下一目标会使累计超过 1000 时立即抛
   :exc:`app.paths.PathCountLimit`（``target`` 指向该目标、``used`` 恒
   为 1001、``limit`` 为 1000），由路由层映射为 409
   ``status=limit``，不构造任何路径列表、不返回部分业务结果；恰好
   累计到 1000 仍成功返回。
"""

from __future__ import annotations

from collections.abc import Collection

from packaging.version import Version

from .audit import _find_candidate
from .paths import PathCountBudget, shortest_paths
from .repository import Repository
from .spdx import (
    DENY,
    UNKNOWN,
    LicenseExpressionError,
    evaluate_spdx_expression,
    parse_spdx_expression,
)


def evaluate_license_policy(
    repo: Repository,
    *,
    root_name: str,
    current_lock: dict[str, Version],
    graph: dict[str, list[str]],
    allow: Collection[str],
    deny: Collection[str],
) -> dict:
    """沿已激活依赖图对每个可达包做许可证三态判定。

    ``graph`` 为 :func:`app.paths.build_locked_graph` 产出的根可达子图
    （节点集恰为锁中全部包）。返回
    ``{"violations": [...], "unknowns": [...]}``，两项均按包名排序。

    处理分两个先后阶段，保证 422 优先于路径预算的 409：

    1. **判定阶段**：按包名顺序对所有可达包完成 SPDX 解析与三态判定，
       全程不查询路径、不触碰路径预算。包的 SPDX 表达式非法时按包名
       顺序命中首个非法包并抛 LicenseExpressionError（定位到包与
       版本）——即使名字靠前的命中包本会耗尽共享路径额度，非法表达式
       仍稳定报 422，结果只取决于快照内容。
    2. **路径阶段**：全部表达式合法后，命中包按包名顺序（violations
       与 unknowns 合在同一条名字序上）逐个查询最短路径，各目标的路径
       条数累计到同一个请求级 :class:`~app.paths.PathCountBudget`
       （上限 1000）：加入下一目标会使累计超限即抛
       :exc:`app.paths.PathCountLimit`（首个超限目标、``used`` 恒为
       1001），不构造路径列表、不返回部分结果。
    """
    # 阶段 1：全部可达包先做 SPDX 解析与三态判定（不触碰路径预算）。
    # 决策表按包名顺序生成，非法表达式在此稳定抛 422——与输入顺序无关，
    # 且优先于阶段 2 的任何 409 status=limit。
    decisions: list[tuple[str, str | None, int]] = []
    for name in sorted(graph):
        locked = current_lock[name]
        cand = _find_candidate(repo, name, locked)  # 有效锁：锁定版本必在快照
        assert cand is not None
        license_text = cand.metadata.license

        decision = UNKNOWN
        if license_text is not None:
            try:
                node = parse_spdx_expression(license_text)
            except LicenseExpressionError as exc:
                raise LicenseExpressionError(
                    f"包 {name}=={locked} 的许可证表达式 {license_text!r}"
                    f" 不是合法的 SPDX 表达式: {exc}"
                ) from exc
            decision = evaluate_spdx_expression(node, allow, deny)
        decisions.append((name, license_text, decision))

    # 阶段 2：所有表达式均合法后，才按同一条包名序为命中包查询最短路径，
    # 条数累计到请求级共享预算；超限即整体放弃（409 status=limit）。
    violations: list[dict] = []
    unknowns: list[dict] = []
    budget = PathCountBudget()
    for name, license_text, decision in decisions:
        if decision == DENY:
            violations.append(_entry(name, graph, root_name, license_text, budget))
        elif decision == UNKNOWN:
            unknowns.append(_entry(name, graph, root_name, license_text, budget))

    return {"violations": violations, "unknowns": unknowns}


def _entry(
    name: str,
    graph: dict[str, list[str]],
    root_name: str,
    license_text: str | None,
    budget: PathCountBudget,
) -> dict:
    """构造一个命中包的输出条目：名称、许可证文本与全部最短根路径。"""
    return {
        "name": name,
        "license": license_text,
        "paths": shortest_paths(graph, root_name, name, budget),
    }
