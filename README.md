# AndroidInjectionTool

基于[Android中的so注入(inject)和挂钩(hook) - For both x86 and arm_ariesjzj的博客-CSDN博客](https://blog.csdn.net/jinzhuojun/article/details/9900105)博客提供的代码，实现了安卓注入，增加了对x86_64系统的支持，并在注入内容中增加了帧率捕获的逻辑，支持按照传入参数（进程名称）选择要注入的进程。目前实现了GOT hook，inline hook方法待完善。