using System;
using System.Collections.Generic;
using System.Linq;

namespace OpenTimeStamp.Tests;

internal static class AssertEx
{
    public static void True(bool condition, string message = null)
    {
        if (!condition) throw new TestFailureException(message ?? "Expected true, but found false.");
    }

    public static void False(bool condition, string message = null) =>
        True(!condition, message ?? "Expected false, but found true.");

    public static void Equal<T>(T expected, T actual, string message = null)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new TestFailureException(message ?? $"Expected <{expected}>, but found <{actual}>.");
    }

    public static void NotEqual<T>(T unexpected, T actual, string message = null)
    {
        if (EqualityComparer<T>.Default.Equals(unexpected, actual))
            throw new TestFailureException(message ?? $"Did not expect <{actual}>.");
    }

    public static void NotNull(object value, string message = null) =>
        True(value is not null, message ?? "Expected a non-null value.");

    public static void SequenceEqual(byte[] expected, byte[] actual, string message = null)
    {
        if (expected is null || actual is null || !expected.SequenceEqual(actual))
            throw new TestFailureException(message ?? $"Byte sequences differ. Expected {Hex(expected)}; actual {Hex(actual)}.");
    }

    public static TException Throws<TException>(Action action, string message = null)
        where TException : Exception
    {
        if (action is null) throw new ArgumentNullException(nameof(action));

        // Distinguish the expected exception from a different test failure.
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }
        catch (Exception exception)
        {
            throw new TestFailureException(
                message ?? $"Expected {typeof(TException).Name}, but caught {exception.GetType().Name}: {exception.Message}",
                exception);
        }

        throw new TestFailureException(message ?? $"Expected {typeof(TException).Name}, but no exception was thrown.");
    }

    public static void Contains(string expectedSubstring, string actual, string message = null) =>
        True(actual?.IndexOf(expectedSubstring, StringComparison.OrdinalIgnoreCase) >= 0,
            message ?? $"Expected <{actual}> to contain <{expectedSubstring}>.");

    private static string Hex(byte[] value) =>
        value is null ? "<null>" : BitConverter.ToString(value).Replace("-", string.Empty);
}

internal sealed class TestFailureException : Exception
{
    public TestFailureException(string message)
        : base(message)
    {
    }

    public TestFailureException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
