using System.Reflection;

using Android.App;
using Android.OS;
using Xamarin.Android.NUnitLite;

namespace xamarin_android
{
    [Activity(Label = "xamarin-android", MainLauncher = true)]
    public class MainActivity : TestSuiteActivity
    {
        //protected override string HostName => "127.0.0.1";

        //protected override int HostPort => 4444;

        protected override void OnCreate(Bundle bundle)
        {
            // tests can be inside the main assembly
            AddTest(Assembly.GetExecutingAssembly());
            // or in any reference assemblies
            // AddTest (typeof (Your.Library.TestClass).Assembly);

            // Once you called base.OnCreate(), you cannot add more assemblies.
            base.OnCreate(bundle);
        }
    }
}
