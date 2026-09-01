# Creation of go-seclog

This package was originally `zapseclog`, a Security Event Logging for Ubuntu Pro's systems,
using the zap logger.
This package was then rewritten using `slog`, and then rewired to support multiple models,
as previously it was written considering only OWASP.

The rewrite was mostly done by Claude Opus 5, with GPT Sol as a reviewer.

The prompt in [initial_plan.md](./initial_plan.md) describes the original request.

This generated the [implementation.md](./implementation.md) specification, which was then
reviewed and changed for some time, until landing on the final version.

After implementing the specification, a [review.md](./review.md) was generated, which
resulted in some changes and fixes in the implementation until the final version (1.0) was
released.
