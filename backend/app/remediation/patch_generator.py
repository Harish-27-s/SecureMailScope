import os
from jinja2 import Environment, FileSystemLoader
import difflib

class PatchGenerator:
    def __init__(self, templates_dir="backend/app/templates"):
        self.env = Environment(loader=FileSystemLoader(templates_dir))
        
    def generate_postfix_patch(self, current_config: str = "") -> str:
        # Assuming current_config is empty if none provided
        template = self.env.get_template("postfix_main.cf.j2")
        recommended = template.render(protocols="!SSLv2, !SSLv3, !TLSv1, !TLSv1.1")
        
        return self._generate_diff("main.cf (original)", "main.cf (hardened)", current_config, recommended)
        
    def generate_dovecot_patch(self, current_config: str = "") -> str:
        template = self.env.get_template("dovecot_10_ssl.conf.j2")
        recommended = template.render(protocols="!SSLv3 !TLSv1 !TLSv1.1")
        
        return self._generate_diff("10-ssl.conf (original)", "10-ssl.conf (hardened)", current_config, recommended)
        
    def _generate_diff(self, old_name, new_name, old_text, new_text):
        old_lines = old_text.splitlines() if old_text else []
        new_lines = new_text.splitlines()
        
        diff = difflib.unified_diff(
            old_lines, new_lines,
            fromfile=old_name, tofile=new_name,
            lineterm=''
        )
        return '\n'.join(diff)
