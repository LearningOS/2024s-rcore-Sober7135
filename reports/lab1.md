# 简答作业

1. 第一个是对 0 这个地址写入数据, 根据 sbi 的定义, 会直接发生 page fault

第二个是在 U mode 使用在 S mode 才能使用的 `sret`, 会直接而发生 Illegal Instruction

第三个是在 U mode 使用在 S mode 才能使用的 `csrr` 和 寄存器 sstatus, 会直接而发生 Illegal Instruction

```
[kernel] PageFault in application, bad addr = 0x0, bad instruction = 0x804003ac, kernel killed it.
[kernel] IllegalInstruction in application, kernel killed it.
[kernel] IllegalInstruction in application, kernel killed it.
```

2. 1. 如果是从`trap_handler`到`__restore`, `a0` 代表了要`__restore`的`TrapContext`; 如果是从`__switch`到`__restore`, 则代表了 current `TaskContext`. 两种使用情景: 一是处理完`trap`从`trap_handler`返回, 然后返回 User mode; 二是 switch task.
   2. - `sstatus`: "Supervisor Status Register", 表示处理器现在的状态, 是在 U mode 还是 S mode.
      - `sepc`: "Supervisor Exception Program Counter", 发生 trap 时, 将会写入发生中断的虚拟地址.
      - `sscratch`: "Supervisor Scratch Register", The sscratch register is an SXLEN-bit read/write register, dedicated for use by the supervisor. Typically, sscratch is used to hold a pointer to the hart-local supervisor context while the hart is executing user code. At the beginning of a trap handler, sscratch is swapped with a user register to provide an initial working register. 简而言之就是用来装用户栈的地址的.
   3. 因为用户态程序不需要用到这俩寄存器, 就不需要存.
   4. `sp` 是 用户栈, `sscratch` 是内核栈.
   5. `sret`. `sret` 用于返回 U mode
   6. `ecall` 或者 违法指令 或者 发生 page fault.

# 报告

实现了一个系统调用, 用于统计当前的 task 的系统调用数量和调度的时间.

# 荣誉准则

1.  在完成本次实验的过程（含此前学习的过程）中，我曾分别与 以下各位 就（与本次实验相关的）以下方面做过交流，还在代码中对应的位置以注释形式记录了具体的交流对象及内容：

无

2.  此外，我也参考了 以下资料 ，还在代码中对应的位置以注释形式记录了具体的参考来源及内容：

无

3.  我独立完成了本次实验除以上方面之外的所有工作，包括代码与文档。 我清楚地知道，从以上方面获得的信息在一定程度上降低了实验难度，可能会影响起评分。

4.  我从未使用过他人的代码，不管是原封不动地复制，还是经过了某些等价转换。 我未曾也不会向他人（含此后各届同学）复制或公开我的实验代码，我有义务妥善保管好它们。 我提交至本实验的评测系统的代码，均无意于破坏或妨碍任何计算机系统的正常运转。 我清楚地知道，以上情况均为本课程纪律所禁止，若违反，对应的实验成绩将按“-100”分计。
