using System;
using Android.OS;
using Xamarin.Android.NUnitLite;

namespace xamarin_android
{
    public abstract class AutomatedTestSuiteActivity : TestSuiteActivity
    {
        protected abstract string HostName { get; }
        protected abstract int HostPort { get; }

        protected override void OnCreate(Bundle bundle)
        {
            Intent.PutExtra("automated", true);
            Intent.PutExtra("remote", true);
            Intent.PutExtra("hostName", this.HostName);
            Intent.PutExtra("hostPort", this.HostPort);

            base.OnCreate(bundle);
        }

        public override void Finish()
        {
            System.Environment.Exit(0);
        }
    }
}
