using FluentValidation.Results;

namespace Recto.Shared.Common;

public static class ValidationResultExtensions
{
    public static Result<T> ToResult<T>(this ValidationResult validationResult)
    {
        if (validationResult.IsValid)
        {
            return Result.Success<T>(default!);
        }

        var validationErrors = validationResult.Errors
            .Select(f => new ValidationErrors(
                PropertyName: f.PropertyName ?? "General",
                ErrorMessage: f.ErrorMessage))
            .ToArray();

        return Result.Failure<T>(Error.Validation(validationErrors));
    }

    public static Result ToResult(this ValidationResult validationResult)
    {
        if (validationResult.IsValid)
        {
            return Result.Success();
        }

        var validationErrors = validationResult.Errors
            .Select(f => new ValidationErrors(
                PropertyName: f.PropertyName ?? "General",
                ErrorMessage: f.ErrorMessage))
            .ToArray();

        return Result.Failure(Error.Validation(validationErrors));
    }
}