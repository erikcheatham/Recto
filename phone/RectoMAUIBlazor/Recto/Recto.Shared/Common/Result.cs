using System.Diagnostics.CodeAnalysis;

namespace Recto.Shared.Common;

public class Result
{
    protected Result(bool isSuccess, Error error, HttpStatus status)
    {
        if (isSuccess && error != Error.None)
        {
            throw new InvalidOperationException();
        }

        if (!isSuccess && error == Error.None)
        {
            throw new InvalidOperationException();
        }

        IsSuccess = isSuccess;
        Error = error;
        Status = status;
    }

    public bool IsSuccess { get; }
    public bool IsNoContent => Status == HttpStatus.NoContent;
    public bool IsFailure => !IsSuccess;
    public HttpStatus Status { get; }
    public Error Error { get; }

    public static Result Success() => new(true, Error.None, HttpStatus.Ok);

    public static Result NoContent() => new(true, Error.None, HttpStatus.NoContent);

    public static Result Failure(Error error) => new(false, error, HttpStatus.BadRequest);

    public static Result<TValue> Success<TValue>(TValue value) => new(value, true, Error.None, HttpStatus.Ok);

    public static Result<TValue> NoContent<TValue>(TValue value) => new(value, true, Error.None, HttpStatus.NoContent);

    public static Result<TValue> Failure<TValue>(Error error) => new(default, false, error, HttpStatus.BadRequest);

    public static Result<TValue> Create<TValue>(TValue? value) =>
        value is not null ? Success(value) : Failure<TValue>(Error.Database());

    public static Result ValidationFailure(IReadOnlyCollection<ValidationErrors> validationErrors)
    {
        return Failure(Error.Validation(validationErrors));
    }

    public static Result<TValue> ValidationFailure<TValue>(IReadOnlyCollection<ValidationErrors> validationErrors)
    {
        return Failure<TValue>(Error.Validation(validationErrors));
    }
}

public class Result<TValue> : Result
{
    private readonly TValue? _value;

    protected internal Result(TValue? value, bool isSuccess, Error error, HttpStatus status)
        : base(isSuccess, error, status) =>
        _value = value;

    [NotNull]
    public TValue Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException("The value of a failure result can not be accessed.");

    public static implicit operator Result<TValue>(TValue? value) => Create(value);
}
