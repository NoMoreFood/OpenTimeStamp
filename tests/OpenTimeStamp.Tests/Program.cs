using System;
using System.Collections.Generic;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace OpenTimeStamp.Tests;

[TestClass]
public sealed class RegressionTests
{
    private static readonly IReadOnlyList<TestCase> AllCases = CreateCases();

    public static IEnumerable<object[]> CaseIndexes
    {
        get
        {
            // Serializable row values let MSTest unfold every case during discovery.
            for (var index = 0; index < AllCases.Count; index++) yield return [index];
        }
    }

    public static string GetCaseDisplayName(MethodInfo methodInfo, object[] data) =>
        AllCases[(int)data[0]].Name;

    [TestMethod]
    [DynamicData(nameof(CaseIndexes), DynamicDataDisplayName = nameof(GetCaseDisplayName))]
    public void RegressionCase(int index)
    {
        var test = AllCases[index];
        try
        {
            test.Body();
        }
        catch (TestSkippedException exception)
        {
            Assert.Inconclusive(exception.Message);
        }
    }

    private static IReadOnlyList<TestCase> CreateCases()
    {
        List<TestCase> tests = [];
        Asn1AndRequestTests.Register(tests);
        ProtocolTests.Register(tests);
        PostQuantumProtocolTests.Register(tests);
        PersistenceAndConfigurationTests.Register(tests);
        WebHandlerTests.Register(tests);
        return tests;
    }
}

internal sealed class TestSkippedException(string message) : Exception(message);

internal sealed class TestCase(string name, Action body)
{
    public string Name { get; } = name;

    public Action Body { get; } = body;
}
