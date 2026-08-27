namespace Recto.Shared.Common;

public record Error(
    string Method,
    string Message,
    string StackTrace,
    IReadOnlyCollection<ValidationErrors>? ValidationErrors = null)
{
    public bool HasValidationErrors => ValidationErrors?.Count > 0;

    // Static helpers for common errors
    public static readonly Error None = new(string.Empty, string.Empty, string.Empty);

    public static Error Validation(IReadOnlyCollection<ValidationErrors> validationErrors, string? customMessage = null)
    {
        var message = customMessage ??
            (validationErrors.Count == 1
                ? validationErrors.First().ErrorMessage
                : "One or more validation errors occurred");

        return new Error("Validation.Failed", message, string.Empty, validationErrors);
    }

    public static Error Internal(string message = "Internal error occurred")
        => new("InternalError", message, string.Empty);

    public static Error NotFound(string message = "Resource not found")
        => new("NotFound", message, string.Empty);

    public static Error Database(string message = "Database error occurred")
        => new("DatabaseError", message, string.Empty);

    public static Error Failure(string message = "Failure error occurred")
        => new("FailureError", message, string.Empty);

    public static Error Problem(string message = "Problem error occurred")
        => new("ProblemError", message, string.Empty);

    public static Error Conflict(string message = "Conflict error occurred")
        => new("ConflictError", message, string.Empty);

}
