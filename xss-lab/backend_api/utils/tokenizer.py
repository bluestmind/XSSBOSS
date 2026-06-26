"""Token generation for Oracle."""
import secrets
import base64
from typing import Optional


class Tokenizer:
    """Generate unique tokens for XSS Oracle callbacks."""
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_short_token(length: int = 16) -> str:
        """Generate a shorter token (for display purposes)."""
        return secrets.token_hex(length)

    @staticmethod
    def replace_token(payload: str, old_token: str, new_token: str) -> str:
        """Replace all representations of old_token with new_token in payload."""
        if not payload or not old_token or not new_token:
            return payload
            
        # 1. Literal replacement
        payload = payload.replace(old_token, new_token)
        
        # 2. Base64 encoded token replacement
        b64_old = base64.b64encode(old_token.encode()).decode()
        b64_new = base64.b64encode(new_token.encode()).decode()
        payload = payload.replace(b64_old, b64_new)
        
        # Strip padding versions of base64
        b64_old_strip = b64_old.rstrip('=')
        b64_new_strip = b64_new.rstrip('=')
        if b64_old_strip and b64_new_strip:
            payload = payload.replace(b64_old_strip, b64_new_strip)
            
        # 3. Base64 encoded eval wrapper replacement (e.g. __XSS__('token'))
        for wrapper_old_tpl, wrapper_new_tpl in [
            (f"__XSS__('{old_token}')", f"__XSS__('{new_token}')"),
            (f"__XSS__(\"{old_token}\")", f"__XSS__(\"{new_token}\")"),
            (f"__XSS__`{old_token}`", f"__XSS__`{new_token}`")
        ]:
            b64_wrap_old = base64.b64encode(wrapper_old_tpl.encode()).decode()
            b64_wrap_new = base64.b64encode(wrapper_new_tpl.encode()).decode()
            payload = payload.replace(b64_wrap_old, b64_wrap_new)
            
            b64_wrap_old_strip = b64_wrap_old.rstrip('=')
            b64_wrap_new_strip = b64_wrap_new.rstrip('=')
            if b64_wrap_old_strip and b64_wrap_new_strip:
                payload = payload.replace(b64_wrap_old_strip, b64_wrap_new_strip)
                
        # 4. String.fromCharCode replacement (decimal ASCII codes)
        ascii_old = ",".join(str(ord(c)) for c in old_token)
        ascii_new = ",".join(str(ord(c)) for c in new_token)
        payload = payload.replace(ascii_old, ascii_new)
        
        return payload

    @staticmethod
    def replace_token_with_placeholders(payload: str, token: str) -> str:
        """Replace all representations of token with specific placeholders."""
        if not payload or not token:
            return payload
            
        # 1. Base64 wrappers (e.g. base64 of __XSS__('token'))
        # We replace the wrapper base64 first because it's longer
        for wrapper_tpl, placeholder in [
            (f"__XSS__('{token}')", "{{TOKEN_WRAPPER_B64}}"),
            (f"__XSS__(\"{token}\")", "{{TOKEN_WRAPPER_B64}}"),
            (f"__XSS__`{token}`", "{{TOKEN_WRAPPER_B64}}")
        ]:
            b64_wrap = base64.b64encode(wrapper_tpl.encode()).decode()
            payload = payload.replace(b64_wrap, placeholder)
            b64_wrap_strip = b64_wrap.rstrip('=')
            if b64_wrap_strip:
                payload = payload.replace(b64_wrap_strip, placeholder)

        # 2. Base64 token
        b64_token = base64.b64encode(token.encode()).decode()
        payload = payload.replace(b64_token, "{{TOKEN_B64}}")
        b64_token_strip = b64_token.rstrip('=')
        if b64_token_strip:
            payload = payload.replace(b64_token_strip, "{{TOKEN_B64}}")
            
        # 3. String.fromCharCode (decimal ASCII codes)
        ascii_vals = ",".join(str(ord(c)) for c in token)
        payload = payload.replace(ascii_vals, "{{TOKEN_CHARCODE}}")
        
        # 4. Literal
        payload = payload.replace(token, "{{TOKEN}}")
        
        return payload

    @staticmethod
    def replace_placeholders_with_token(payload: str, token: str) -> str:
        """Replace placeholders back with the new token representations."""
        if not payload or not token:
            return payload
            
        # We must compute the encodings for the new token
        b64_token = base64.b64encode(token.encode()).decode()
        b64_token_strip = b64_token.rstrip('=')
        
        b64_wrap = base64.b64encode(f"__XSS__('{token}')".encode()).decode()
        b64_wrap_strip = b64_wrap.rstrip('=')
        
        ascii_vals = ",".join(str(ord(c)) for c in token)
        
        # Replace placeholders
        payload = payload.replace("{{TOKEN_WRAPPER_B64}}", b64_wrap_strip)
        payload = payload.replace("{{TOKEN_B64}}", b64_token_strip)
        payload = payload.replace("{{TOKEN_CHARCODE}}", ascii_vals)
        payload = payload.replace("{{TOKEN}}", token)
        
        return payload



