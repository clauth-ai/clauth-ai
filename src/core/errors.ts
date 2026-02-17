export class ClauthError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(code: string, message: string, statusCode = 400) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.name = "ClauthError";
  }
}

export class AccessDeniedError extends ClauthError {
  constructor(message: string) {
    super("ACCESS_DENIED", message, 403);
  }
}

export class NotFoundError extends ClauthError {
  constructor(message: string) {
    super("NOT_FOUND", message, 404);
  }
}

export class ValidationError extends ClauthError {
  constructor(message: string) {
    super("VALIDATION_ERROR", message, 422);
  }
}
