# -*- coding: utf-8 -*-
"""Mixin 组合契约:把「Mixin 引用什么、组合体定义什么」从口头约定钉成测试。

Why this file exists
--------------------
scanner.py 顶部的 ``# noqa: F401  (Mixin 运行时引用...)`` 就是这个契约的形态:
``Scanner(StoredBlindMixin, AdvancedLayerMixin, CrawlMixin)`` 的可用面是**组合后
的并集**,静态分析看不见,新人更看不见。Mixin 里一句 ``self.requester.send(...)``
依赖核心类在 ``__init__`` 里造好的属性;核心类一句 ``self._scan_dom_page(...)``
依赖某个 Mixin 带进来的方法——这些链接没有任何语法保证,改名一侧另一侧只在
运行时(而且是到达那条路径时)才炸;若炸在层分发器里,还会被 layer_guard 按
Duck-typing 异常吞成 DEBUG,于是又造出一个「实现完整、永远不工作」的静默失效
(README 归档 Phase 122/125 的形状)。

本文件用 AST 把契约显式化:对每个组合体(sync Scanner / async AsyncScanner /
_AsyncScannerShim),断言**任何一个成员里被引用的 ``self.X`` 都在组合体并集里
有定义**(方法 def / 类属性 / self.X 赋值 三处任一)。这不证明语义正确——语义
由各靶场与单测管;但「名字接得上」是纯机械事实,没有理由让它只能靠运行时暴露。

防空转护栏(Phase 201 续四:守卫空转的失效形状):

- 结构守卫:组合声明(基类列表)变了就 loud fail,静默并入核心类不允许——
  新增/删除 Mixin 必须回来登记;
- 非空守卫:每个 Mixin 必须真的引用**组合体外**的名字,否则对它的守护测了
  表示没测被测物;
- allowlist 每一项必须**确实**在组合体里无定义——把「外部注入」记成账,
  而不是把守卫开成可以随便增删的豁免名单。
"""
import ast
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_CORE = os.path.join(_ROOT, "xssentinel", "core")

# 组合体声明:第一个成员是核心类,其余是 Mixin。顺序即组合声明顺序。
# 核心类的基类列表由 test_composition_declaration_matches_the_actual_bases 钉住:
# 增删 Mixin 或改组合形状,这里必须同步登记,否则 loud fail。
HIERARCHIES = {
    "Scanner (sync)": (
        ("scanner.py", "Scanner"),
        ("scanner_stored.py", "StoredBlindMixin"),
        ("scanner_stored_auto.py", "StoredAutoMixin"),
        ("scanner_layers.py", "AdvancedLayerMixin"),
        ("scanner_crawl.py", "CrawlMixin"),
    ),
    "AsyncScanner (async)": (
        ("async_scanner.py", "AsyncScanner"),
        ("async_scanner_verify.py", "AsyncHeadlessVerifyMixin"),
        ("async_scanner_layers.py", "AsyncDetectionLayersMixin"),
        ("async_scanner_crawl.py", "AsyncCrawlMixin"),
    ),
    "_AsyncScannerShim (async CLI 的 sync-mixin 适配体)": (
        ("async_scanner_common.py", "_AsyncScannerShim"),
        ("scanner_stored.py", "StoredBlindMixin"),
        ("scanner_stored_auto.py", "StoredAutoMixin"),
        ("scanner_layers.py", "AdvancedLayerMixin"),
        ("scanner_crawl.py", "CrawlMixin"),
    ),
}

# 外部注入的 self 名单:由组合体之外的代码在构造后赋值(如 CLI runner)。
# key = (组合体名, 类名, 属性名);value = 注入点。保持为空直到真的出现——
# test_allowlist_entries_are_undefined 会拒绝把组合体里本来就有定义的名字写进来。
EXTERNAL_INJECTION = {}

_cache = {}


def _module_ast(module):
    if module not in _cache:
        with open(os.path.join(_CORE, module), encoding="utf-8") as fh:
            _cache[module] = ast.parse(fh.read(), filename=module)
    return _cache[module]


def _find_class(module, cls):
    for node in ast.walk(_module_ast(module)):
        if isinstance(node, ast.ClassDef) and node.name == cls:
            return node
    raise AssertionError(
        f"{module} no longer defines class {cls!r} -- 组合声明变了,"
        "请同步更新 test_mixin_contracts.HIERARCHIES")


def _is_self(node):
    return isinstance(node, ast.Name) and node.id == "self"


def _defined_names(cls_node):
    """组合体成员提供的名字:方法/属性 def、类属性、self.X 赋值(含增赋)。"""
    names = set()
    for stmt in cls_node.body:  # 方法 def 只认类体直接子节点(嵌套函数不算成员)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(stmt.name)
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)  # 类属性 X = ...
    for node in ast.walk(cls_node):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
        elif (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name) and node.func.id == "setattr"
                and node.args and _is_self(node.args[0])
                and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)):
            names.add(node.args[1].value)  # setattr(self, "X", ...)
            continue
        else:
            continue
        for t in targets:
            if isinstance(t, ast.Attribute) and _is_self(t.value):
                names.add(t.attr)  # self.X = ... / self.X += ...
    return names


def _referenced_names(cls_node):
    """成员里被读取的 self.X(方法调用也是 Attribute Load)。

    ``getattr(self, "X", ...)`` 的字面量形态同样是对组合体的引用——本文件
    首版漏掉它时,AsyncHeadlessVerifyMixin(全程 getattr 守卫式访问)被误判成
    「不依赖组合体」。``self.__class__`` 之类 dunder 不属组合契约,照旧排除。
    """
    refs = set()
    for node in ast.walk(cls_node):
        if (isinstance(node, ast.Attribute) and _is_self(node.value)
                and isinstance(node.ctx, ast.Load)
                and not node.attr.startswith("__")):  # dunder/改名不属组合契约
            refs.add(node.attr)
        elif (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("getattr", "setattr", "hasattr")
                and node.args and _is_self(node.args[0])
                and node.args[1:] and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
                and not node.args[1].value.startswith("__")):
            # getattr/setattr/hasattr(self, "X", ...) —— getattr/hasattr 是引用,
            # setattr 是定义;按引用收进来,定义侧由 _defined_names 的 self.X 赋值
            # 与下面的 setattr 分支共同覆盖。
            refs.add(node.args[1].value)
    return refs


def _composition_nodes(hier):
    return [(mod, cls, _find_class(mod, cls)) for mod, cls in HIERARCHIES[hier]]


def test_composition_declaration_matches_the_actual_bases():
    """核心类的基类列表必须与登记一致——新增/删除 Mixin 必须回来登记。"""
    for hier, members in HIERARCHIES.items():
        core_mod, core_cls, core_node = _composition_nodes(hier)[0]
        expected = {cls for _, cls in members[1:]}
        actual = {b.id for b in core_node.bases if isinstance(b, ast.Name)}
        assert actual == expected, (
            f"{core_mod}:{core_cls} 的基类是 {sorted(actual)},登记的是 "
            f"{sorted(expected)}——组合形状变了,请同步 HIERARCHIES(并检查"
            "新 Mixin 的 self 引用是否接得上)")


def test_every_self_reference_resolves_within_each_composition():
    """组合体并集必须定义所有成员引用的 self 名字——契约本体。"""
    for hier, members in HIERARCHIES.items():
        nodes = _composition_nodes(hier)
        defined = set()
        for _, _, node in nodes:
            defined |= _defined_names(node)
        for mod, cls, node in nodes:
            missing = _referenced_names(node) - defined
            missing = {
                n for n in missing
                if (hier, cls, n) not in EXTERNAL_INJECTION
            }
            assert not missing, (
                f"{hier}: {mod}:{cls} 引用了组合体未定义的 self 名字 "
                f"{sorted(missing)}——改名/搬代码断掉了隐式契约,接回组合体"
                "或(确系外部注入时)登记 EXTERNAL_INJECTION 并写明注入点")


def test_each_mixin_actually_depends_on_the_composition():
    """Mixin 若不引用组合体外任何名字,对它的守护是空转(测了表示没测被测物)。"""
    for hier, members in HIERARCHIES.items():
        for mod, cls, node in _composition_nodes(hier)[1:]:
            external = _referenced_names(node) - _defined_names(node)
            assert external, (
                f"{hier}: {mod}:{cls} 不再引用组合体外任何名字——它已自成一体,"
                "本文件的契约守卫对它是空转;请确认它是否还该留在组合里")


def test_allowlist_entries_are_undefined():
    """EXTERNAL_INJECTION 只许登记组合体里确实没有的名字(不把守卫开成豁免名单)。"""
    for hier, members in HIERARCHIES.items():
        defined = set()
        for _, _, node in _composition_nodes(hier):
            defined |= _defined_names(node)
        for (h, cls, name), where in EXTERNAL_INJECTION.items():
            if h != hier:
                continue
            assert name not in defined, (
                f"EXTERNAL_INJECTION[{h}, {cls}, {name}] 的名字在组合体里已有定义"
                "——它是契约缺口,不是外部注入;请从名单里删掉并修接线")
            assert where, f"EXTERNAL_INJECTION[{h}, {cls}, {name}] 缺少注入点说明"


# ---------------------------------------------------------------------------
# 本文件抓出的第一个真实缺口的行为级回归。AST 测试只证明「名字有定义」;
# 这条证明 shim 上的 `_dom_engine` 是**惰性**委托——构造 shim 不得提前触发
# playwright 解析(那是 AsyncScanner 每次进入 DOM 层才做的事),访问时必须
# 委托到 async 侧同名解析器,而不是给个静态 None 了事(那样 static 之外的
# 配置在 shim 上会被静默降级)。
# ---------------------------------------------------------------------------
_SENTINEL_ENGINE = object()


class _StubAsyncScanner:
    """足以撑起 _AsyncScannerShim.__init__ 的最小替身,其余属性走 getattr 兜底。"""

    def __init__(self):
        self.verbose = False
        self.waf_name = None
        self.coverage = None
        self.json_body = None
        self.oob = None
        self._oob_started = False
        self.max_payloads = 14
        self.skip_params = {"debug"}   # 操作者 --skip-param 的替身
        self.xsleak_audit = True       # 操作者 --audit-xs-leaks 的替身
        self.crawl_depth = 3           # async BFS 深度的替身
        self.resolver_calls = 0

    def _resolve_dom_engine(self):
        self.resolver_calls += 1
        return _SENTINEL_ENGINE

    def __getattr__(self, name):
        return None


def test_shim_satisfies_sync_dom_contract():
    """shim 继承了 sync 的 _scan_dom,就必须接得上它的 self._dom_engine。"""
    from xssentinel.core.async_scanner_common import _AsyncScannerShim
    stub = _StubAsyncScanner()
    shim = _AsyncScannerShim(stub)
    assert stub.resolver_calls == 0, (
        "构造 shim 就解析了 DOM 引擎——惰性没了:未跑 DOM 层的目标也要付 "
        "playwright 可用性探测的成本")
    assert shim._dom_engine is _SENTINEL_ENGINE, (
        "_dom_engine 必须委托 async 侧解析器(同一次扫描语义一致),"
        "而不是硬编码 None/static")
    assert stub.resolver_calls == 1


def test_shim_proxies_operator_flags():
    """--skip-param / --audit-xs-leaks 必须穿透到 shim:缺了它们,继承的
    _mine_hidden_params 会把操作者点名跳过的参数照挖不误(async 挖矿路径
    实测经 shim._mine_hidden_params -> getattr(self, "skip_params", None))。"""
    from xssentinel.core.async_scanner_common import _AsyncScannerShim
    shim = _AsyncScannerShim(_StubAsyncScanner())
    assert shim.skip_params == {"debug"}, (
        "shim 丢了 skip_params——async 引擎的隐藏参数挖矿会无视 --skip-param")
    assert shim.xsleak_audit is True, (
        "shim 丢了 xsleak_audit——继承的 _scan_xsleak_audit 会静默不审计")
    assert shim.crawl_depth == 3, (
        "shim 丢了 crawl_depth——继承的 _crawl/_crawl_spa 直读它,缺了就是 "
        "AttributeError(layer_guard 会把它吞成 DEBUG)")
    assert shim.scope is None, (
        "shim 的 scope 应代理 async 的值(async 不实现 --scope,即 None 不限域)")
