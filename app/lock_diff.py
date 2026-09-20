"""两份锁定清单的差异比较（POST /lock-diff）。

调用本模块前，``before_lock`` 与 ``after_lock`` 已**各自独立**通过
:func:`app.audit.audit_lock` 的同一套审计规则（无 missing / unavailable /
constraint_mismatch / extraneous）。因此这里不做任何版本选择与约束核对，
只沿两份锁各自的**已激活依赖图**（与 /dependency-paths 同一张图：按锁定
版本、目标环境下 marker 求值后激活的依赖）比较**根可达包**：

* ``added``      仅在 after 根可达集合中的包（before_paths 恒为空）；
* ``removed``    仅在 before 根可达集合中的包（after_paths 恒为空）；
* ``upgraded``   两侧均可达，after 锁定版本严格高于 before（PEP 440）；
* ``downgraded`` 两侧均可达，after 锁定版本严格低于 before（PEP 440）。

PEP 440 等价的版本（``1.0`` 与 ``1.0.0``）不产生变化项。每个变化项同时
给出其在前后依赖图中从根包出发的**全部最短根路径**（语义与
/dependency-paths 一致：菱形等长路径全保留、环安全、字典序确定性排序）；
在某一侧不可达的变化项（added/removed）该侧路径为空数组 ``[]``。

四类变化各自只取决于快照、目标环境与两份锁定清单，列表均按规范化包名
排序；结果与输入（包键 / 候选列表 / 锁键）顺序无关。一次请求中**所有
变化项待返回的最短路径共享同一个请求级预算**
（app.paths.PATH_COUNT_LIMIT，1000 条；added/removed 只有一侧路径，
升降级项前后两侧各计一次）：变化项按既有顺序
（added → removed → upgraded/downgraded，各按包名；每项内先
before_paths 后 after_paths）逐个查询并跨 before/after 两侧累计条数，
加入下一查询会使累计超过 1000 时立即抛 :exc:`app.paths.PathCountLimit`
（``target`` 指向该变化项、``used`` 恒为 1001、``limit`` 为 1000），
由路由层映射为 409 ``status=limit``，不构造任何路径列表、不返回部分
业务结果；恰好累计到 1000 仍成功返回。
"""

from __future__ import annotations

from packaging.version import Version

from .paths import PathCountBudget, build_locked_graph, shortest_paths
from .repository import Repository


def diff_locks(
    repo: Repository,
    *,
    root_name: str,
    before_lock: dict[str, Version],
    after_lock: dict[str, Version],
) -> dict:
    """比较两份**已通过审计**的锁定清单，返回四类根可达包变化。

    入参为同一份仓库快照与同一目标环境下解析出的两份锁（版本为 PEP 440
    Version）。返回 ``{"added", "removed", "upgraded", "downgraded"}``
    四个列表，各列表按规范化包名排序；每项含名称、前后版本与前后侧的
    全部最短根路径（不可达一侧为 ``[]``）。所有变化项的路径条数跨
    before/after 两侧累计到同一个请求级
    :class:`~app.paths.PathCountBudget`（上限 1000），按 added、
    removed、upgraded/downgraded 各类内部按包名、项内先 before 后
    after 的既有顺序逐个查询：加入下一查询会使累计超限即抛
    :exc:`app.paths.PathCountLimit`（指向首个超限变化项、``used`` 恒为
    1001），不构造路径列表、不返回部分结果。
    """
    before_graph = build_locked_graph(
        repo, root_name=root_name, current_lock=before_lock
    )
    after_graph = build_locked_graph(
        repo, root_name=root_name, current_lock=after_lock
    )
    before_reachable = set(before_graph)
    after_reachable = set(after_graph)

    # 请求级共享预算：所有变化项在 before/after 两侧的路径条数合在一起
    # 累计 1000 条额度，按下面的既有确定性顺序逐个查询。
    budget = PathCountBudget()
    added: list[dict] = []
    removed: list[dict] = []
    upgraded: list[dict] = []
    downgraded: list[dict] = []

    for name in sorted(after_reachable - before_reachable):
        added.append({
            "name": name,
            "before_version": None,
            "after_version": str(after_lock[name]),
            "before_paths": [],
            "after_paths": shortest_paths(after_graph, root_name, name, budget),
        })

    for name in sorted(before_reachable - after_reachable):
        removed.append({
            "name": name,
            "before_version": str(before_lock[name]),
            "after_version": None,
            "before_paths": shortest_paths(before_graph, root_name, name, budget),
            "after_paths": [],
        })

    for name in sorted(before_reachable & after_reachable):
        old = before_lock[name]
        new = after_lock[name]
        if old == new:
            # PEP 440 等价版本（1.0 与 1.0.0）不产生变化项。
            continue
        entry = {
            "name": name,
            "before_version": str(old),
            "after_version": str(new),
            "before_paths": shortest_paths(before_graph, root_name, name, budget),
            "after_paths": shortest_paths(after_graph, root_name, name, budget),
        }
        if new > old:
            upgraded.append(entry)
        else:
            downgraded.append(entry)

    return {
        "added": added,
        "removed": removed,
        "upgraded": upgraded,
        "downgraded": downgraded,
    }
