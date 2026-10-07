/* Minimal stand-in for a sanitizer: markup is escaped before it is used. */
function sanitize(value) {
    return String(value).replace(/[&<>"']/g, function (character) {
        return '&#' + character.charCodeAt(0) + ';';
    });
}
