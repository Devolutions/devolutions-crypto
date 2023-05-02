using System.IO;
using System.Reflection;
using AppKit;
using NUnitLite;

namespace xamarinmacmodern
{
    static class MainClass
    {
        static void Main(string[] args)
        {
            new AutoRun(Assembly.GetExecutingAssembly()).Execute(new string[] { "--out=../../../../../TestResult.xml"});
        }
    }
}
