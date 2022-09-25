# cracking writeup
## 0protection

[ELF x86 - 0protection](https://www.root-me.org/en/Challenges/Cracking/ELF-x86-Basic)

程序很简单, 调用getString获取输入，之后调用strcmp比较输入和"123456789"是否相同，使用strings直接可以看到这个字符串。

## basic
[ELF x86 - Basic](http://challenge01.root-me.org/cracking/ch2/ch2.zip)

- 程序流程先读入一个字符串作为username，然后将该username和字符串"john"比较，
- 之后读入一个字符串password，将password字符串与字符串"the ripper"比较，相同的话输出密码。

## no software breakpoints

[ELF x86 - No software breakpoints](http://challenge01.root-me.org/cracking/ch20/ch20.bin)

程序功能很简单，输入密码，密码正确即可，
- 程序只有两个函数，分别为start函数和sub\_8048115函数
- 程序首先调用函数sub\_8048115, 传入参数为代码段中存在代码的开始地址和结束地址，之后为一个字节一个字节读入整个程序的代码段中包含的代码的部分，将指令内容加到ecx上，并不断将ecx左移三位，得到最终的ecx值。
- 之后利用ecx值和输入的密码计算得到一个新的字符串与程序中的字符串相比，符合则输入密码正确。
- 使用调试器的软件断点的时候，会修改代码段为0xcc，此时计算的ecx不是原本的程序无调试运行计算的结果。使用该值无法反推出正确的输入密码。
- 为了避免使用软件断点，先在计算hash值之前插入软件断点，运行之后删除软件断点，插入硬件断点，计算得到正确的ecx值即可，利用该ecx值与程序中的字符串反推出输入字符串。
- 通过ecx值反推密码的程序为exp.c。
