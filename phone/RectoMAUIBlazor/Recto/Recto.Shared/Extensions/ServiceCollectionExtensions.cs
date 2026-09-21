using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using FluentValidation;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Recto.Shared.Common.Handlers;
using Recto.Shared.Services;
using Scrutor;

namespace Recto.Shared.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Wires up the Recto.Shared service surface for the calling host.
    /// Today this registers the v0.4 bootloader client (with cert pinning),
    /// validators, and the handler-discovery scaffold. Concrete handlers
    /// + further services land as later sprints add them.
    /// </summary>
    public static IServiceCollection AddSharedServices(
        this IServiceCollection services,
        IConfiguration configuration,
        bool isClient = false)
    {
        _ = configuration;
        _ = isClient;

        // Cert pinning service (round 6). Singleton, in-memory; pins are
        // restored from PairingState at app-start by Home.razor.
        services.AddSingleton<IPinningService, PinningService>();

        // FluentValidation: discovers any AbstractValidator<T> in this assembly.
        services.AddValidatorsFromAssembly(typeof(ServiceCollectionExtensions).Assembly);

        // Scrutor: wires concrete IQueryHandler / ICommandHandler implementations.
        // No-op today (no handlers exist yet); auto-registers as we add them.
        services.Scan(scan => scan
            .FromAssemblies(typeof(ServiceCollectionExtensions).Assembly)
            .AddClasses(classes => classes.AssignableTo(typeof(IQueryHandler<,>)))
                .AsImplementedInterfaces()
                .WithScopedLifetime()
            .AddClasses(classes => classes.AssignableTo(typeof(ICommandHandler<>)))
                .AsImplementedInterfaces()
                .WithScopedLifetime()
            .AddClasses(classes => classes.AssignableTo(typeof(ICommandHandler<,>)))
                .AsImplementedInterfaces()
                .WithScopedLifetime());

        // v0.4 bootloader client. BaseAddress is set per-call (one client can talk
        // to whichever bootloader the operator points at). 15s timeout, no Polly
        // retry (pairing is user-initiated; on failure the user just clicks Pair
        // again). Cert validation goes through IPinningService (round 6) so
        // pinned hosts verify against the SPKI captured at pairing time, and
        // un-pinned hosts fall back to system trust.
        services.AddHttpClient<IBootloaderClient, BootloaderClient>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(15);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .ConfigurePrimaryHttpMessageHandler(provider =>
        {
            var pinning = provider.GetRequiredService<IPinningService>();
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (req, cert, chain, errors) =>
            {
                if (cert is null || req.RequestUri is null)
                {
                    return false;
                }
                var host = req.RequestUri.Host;
                var actualSpki = CertPinHelpers.ComputeSpkiPin(cert);
                return pinning.Validate(host, actualSpki, errors == SslPolicyErrors.None);
            };
            return handler;
        });

        // Decorator pipeline (validation + logging) wires in once concrete handlers exist:
        //   services.Decorate(typeof(ICommandHandler<,>), typeof(ValidationDecorator.CommandHandler<,>));
        //   services.Decorate(typeof(ICommandHandler<>), typeof(ValidationDecorator.CommandBaseHandler<>));
        //   services.Decorate(typeof(ICommandHandler<,>), typeof(LoggingDecorator.CommandHandler<,>));
        //   services.Decorate(typeof(ICommandHandler<>), typeof(LoggingDecorator.CommandBaseHandler<>));
        //   services.Decorate(typeof(IQueryHandler<,>), typeof(LoggingDecorator.QueryHandler<,>));

        return services;
    }
}
