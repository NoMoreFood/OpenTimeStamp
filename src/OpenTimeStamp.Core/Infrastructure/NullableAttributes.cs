// .NET Framework 4.8 does not define these flow annotations. The compiler recognizes them by name, so
// declaring them here lets nullable analysis follow Try-pattern results across assemblies.
namespace System.Diagnostics.CodeAnalysis;

[AttributeUsage(AttributeTargets.Parameter)]
internal sealed class NotNullWhenAttribute(bool returnValue) : Attribute
{
    public bool ReturnValue { get; } = returnValue;
}

[AttributeUsage(
    AttributeTargets.Parameter | AttributeTargets.Property | AttributeTargets.ReturnValue, AllowMultiple = true)]
internal sealed class NotNullIfNotNullAttribute(string parameterName) : Attribute
{
    public string ParameterName { get; } = parameterName;
}

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
internal sealed class MemberNotNullAttribute(params string[] members) : Attribute
{
    public string[] Members { get; } = members;
}
