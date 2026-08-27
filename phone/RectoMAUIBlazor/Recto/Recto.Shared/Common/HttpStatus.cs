namespace Recto.Shared.Common;

public record HttpStatus(int Code, string Message)
{
    // 200 Success
    public static readonly HttpStatus Ok = new(200, "OK");
    public static readonly HttpStatus NoContent = new(204, "No Content");

    // 400 Client Errors
    public static readonly HttpStatus BadRequest = new(400, "Bad Request");
    public static readonly HttpStatus Unauthorized = new(401, "Unauthorized");
    public static readonly HttpStatus NotFound = new(404, "Not Found");

    // 500 Server Errors
    public static readonly HttpStatus InternalServerError = new(500, "Internal Server Error");
    public static readonly HttpStatus NotImplemented = new(501, "Not Implemented");
    public static readonly HttpStatus BadGateway = new(502, "Bad Gateway");

    // Custom errors if needed
    public static readonly HttpStatus ContractMismatch = new(400, "Contract Mismatch");
    public static readonly HttpStatus NullValue = new(400, "Null Value");
    public static readonly HttpStatus ConditionNotMet = new(412, "Precondition Failed");
}
