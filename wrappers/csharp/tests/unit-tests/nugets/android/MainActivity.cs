namespace android;

using System;
using System.Linq;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[Activity(Label = "@string/app_name", MainLauncher = true)]
public class MainActivity : Activity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // Set our view from the "main" layout resource
        SetContentView(Resource.Layout.activity_main);

        		int passedTests = 0;
        int failedTests = 0;

		// Get the current assembly
		Assembly currentAssembly = Assembly.GetExecutingAssembly();

		// Find all classes with the [TestClass] attribute
		var testClasses = currentAssembly.GetTypes()
			.Where(t => t.GetCustomAttributes(typeof(TestClassAttribute), false).Any());

		foreach (var testClass in testClasses)
		{
			Console.WriteLine($"Running tests in {testClass.Name}...");

			// Create an instance of the test class
			var testClassInstance = Activator.CreateInstance(testClass);

			// Find all methods with the [TestMethod] attribute
			var testMethods = testClass.GetMethods()
				.Where(m => m.GetCustomAttributes(typeof(TestMethodAttribute), false).Any());

			foreach (var testMethod in testMethods)
			{
				try
				{
					Console.WriteLine($"Running {testMethod.Name}...");
					testMethod.Invoke(testClassInstance, null);
					Console.WriteLine($"{testMethod.Name} passed.");
					passedTests++;
				}
				catch (TargetInvocationException ex) when (ex.InnerException is AssertFailedException)
				{
					Console.WriteLine($"{testMethod.Name} failed: {ex.InnerException.Message}");
					failedTests++;
				}
				catch (Exception ex)
				{
					Console.WriteLine($"{testMethod.Name} encountered an unexpected error: {ex.Message}");
					failedTests++;
				}
			}
		}

		// Summary
		Console.WriteLine("\nTest Summary:");
		Console.WriteLine($"Passed: {passedTests}");
		Console.WriteLine($"Failed: {failedTests}");

		// Exit with non-zero code if any tests failed
		if (failedTests > 0)
		{
			Environment.Exit(1);
		}

        Environment.Exit(0);
    }
}