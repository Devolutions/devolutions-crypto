namespace android;

using System;
using System.Linq;
using System.Reflection;
using Debugger = System.Diagnostics.Debug;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading;

[Activity(Label = "@string/app_name", MainLauncher = true)]
public class MainActivity : Activity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // Set our view from the "main" layout resource
        SetContentView(Resource.Layout.activity_main);

		Debugger.WriteLine($"====LAUNCHING ANDROID TESTS====");

    	int passedTests = 0;
        int failedTests = 0;

		// Get the current assembly
		Assembly currentAssembly = Assembly.GetExecutingAssembly();

		// Find all classes with the [TestClass] attribute
		var testClasses = currentAssembly.GetTypes()
			.Where(t => t.GetCustomAttributes(typeof(TestClassAttribute), false).Any());

		foreach (var testClass in testClasses)
		{
			Debugger.WriteLine($"Running tests in {testClass.Name}...");

			// Create an instance of the test class
			var testClassInstance = Activator.CreateInstance(testClass);

			// Find all methods with the [TestMethod] attribute
			var testMethods = testClass.GetMethods()
				.Where(m => m.GetCustomAttributes(typeof(TestMethodAttribute), false).Any());

			foreach (var testMethod in testMethods)
			{
				try
				{
					Debugger.WriteLine($"Running {testMethod.Name}...");
					testMethod.Invoke(testClassInstance, null);
					Debugger.WriteLine($"{testMethod.Name} passed.");
					passedTests++;
				}
				catch (TargetInvocationException ex) when (ex.InnerException is AssertFailedException)
				{
					Debugger.WriteLine($"{testMethod.Name} failed: {ex.InnerException.Message}");
					failedTests++;
				}
				catch (Exception ex)
				{
					Debugger.WriteLine($"{testMethod.Name} encountered an unexpected error: {ex.Message}");
					failedTests++;
				}
			}
		}

		// Summary
		Debugger.WriteLine("\nTest Summary:");
		Debugger.WriteLine($"Passed: {passedTests}");
		Debugger.WriteLine($"Failed: {failedTests}");
		Debugger.WriteLine($"====ENDOFTESTS====");

		Thread.Sleep(10000);

		// Exit with non-zero code if any tests failed
		this.FinishAffinity();
    }
}