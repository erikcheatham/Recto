using Recto.Shared.Common.Handlers;
using FluentValidation;
using FluentValidation.Results;

namespace Recto.Shared.Common.Decorator;

internal static class ValidationDecorator
{
    internal sealed class CommandHandler<TCommand, TResponse>(
        ICommandHandler<TCommand, TResponse> innerHandler,
        IEnumerable<IValidator<TCommand>> validators)
        : ICommandHandler<TCommand, TResponse>
        where TCommand : ICommand<TResponse>
    {
        public async Task<Result<TResponse>> Handle(TCommand command, CancellationToken cancellationToken)
        {
            ValidationFailure[] validationFailures = await ValidateAsync(command, validators);

            if (validationFailures.Length == 0)
            {
                return await innerHandler.Handle(command, cancellationToken);
            }

            return Result.Failure<TResponse>(CreateValidationError(validationFailures));
        }
    }

    internal sealed class CommandBaseHandler<TCommand>(
        ICommandHandler<TCommand> innerHandler,
        IEnumerable<IValidator<TCommand>> validators)
        : ICommandHandler<TCommand>
        where TCommand : ICommand
    {
        public async Task<Result> Handle(TCommand command, CancellationToken cancellationToken)
        {
            ValidationFailure[] validationFailures = await ValidateAsync(command, validators);

            if (validationFailures.Length == 0)
            {
                return await innerHandler.Handle(command, cancellationToken);
            }

            return Result.Failure(CreateValidationError(validationFailures));
        }
    }

    private static async Task<ValidationFailure[]> ValidateAsync<TCommand>(
        TCommand command,
        IEnumerable<IValidator<TCommand>> validators)
    {
        if (!validators.Any())
        {
            return Array.Empty<ValidationFailure>();
        }

        var context = new ValidationContext<TCommand>(command);

        ValidationResult[] validationResults = await Task.WhenAll(
            validators.Select(validator => validator.ValidateAsync(context)));

        ValidationFailure[] validationFailures = validationResults
            .Where(validationResult => !validationResult.IsValid)
            .SelectMany(validationResult => validationResult.Errors)
            .ToArray();

        return validationFailures;
    }

    private static Error CreateValidationError(ValidationFailure[] validationFailures)
    {
        if (validationFailures == null || validationFailures.Length == 0)
        {
            return Error.Problem("Validation failed with no details.");
        }

        // Build a concise message listing property -> error message.
        var details = validationFailures
            .Select(f =>
            {
                var prop = string.IsNullOrWhiteSpace(f.PropertyName) ? "<root>" : f.PropertyName;
                return $"{prop}: {f.ErrorMessage}";
            })
            .ToArray();

        var message = "Validation failed: " + string.Join("; ", details);

        return Error.Problem(message);
    }
}
