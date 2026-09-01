# AGENTS

Guidelines for AI coding agents and contributors working with the go-seclog package.

## Package overview

`go-seclog` is a package for managing Security Event Logging in a common pattern. It is designed to easily
follow the standards using a common API.

## Important Notes for AI Assistants

### Understanding Context

1. **Read existing code** in the same module before suggesting changes;
2. **Check test patterns** in the same directory to match style;
3. **Review related models** when working with database code;
4. **ASCII-only** text, unless specifically testing something that requires Unicode;
5. **American English only** for all new content.

### Making Changes

1. **Minimal modifications**: Change only what's necessary;
2. **Follow patterns**: Match existing code style and structure;
3. **Test thoroughly**: Run relevant tests after changes;
4. **Update documentation**: When making changes, always check existing documentation (e.g. example code, README.md, godoc strings);
