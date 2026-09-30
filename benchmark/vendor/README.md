# Vendored 第三方文件

这里放的是**测试用、仓库自带**的第三方产物，目的是让基准与测试离线可跑、
不依赖 CDN（CI 与本机都不能假设外网稳定）。

## jquery.min.js

- 版本：jQuery 3.7.1
- 来源：`https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js`
- 许可：MIT（OpenJS Foundation）。文件头自带版权声明。
- 用途：`benchmark/sink_matrix.py` 的每个形状页面都加载它，用来验证
  `dom_engine.wrapJQ()` 包装的 jQuery sink；`benchmark/sink_execution.py`
  用 `page.add_script_tag(path=...)` 注入它来量执行性。

升级时请连同 `_JQ_SHAPES` / `SINKS` 里 jQuery 形状的实测结果一起重跑一遍——
换了版本，"哪些方法真的执行"的结论需要重新测量。
