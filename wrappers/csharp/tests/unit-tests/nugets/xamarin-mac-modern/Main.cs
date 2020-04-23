using System.IO;
using System.Reflection;
using AppKit;

namespace xamarinmacmodern
{
    static class MainClass
    {
        static void Main(string[] args)
        {
            string resultFile = Path.Combine(Assembly.GetExecutingAssembly().Location.Split("bin/Debug")[0], "TestResult.xml");

            string[] testArgs = new string[] { Assembly.GetExecutingAssembly().Location, "-noheader", "-xml:" + resultFile };
            GuiUnit.TestRunner.Main(testArgs);

            //NSApplication.Init();
            //NSApplication.Main(args);
        }
    }
}
