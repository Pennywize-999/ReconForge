import os
from jinja2 import Environment, FileSystemLoader
from sentinelrecon.core.models import Target


class HTMLReporter:
    def __init__(self):
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def report(self, target: Target, output_path: str):
        template = self.env.get_template("report.html")
        html_out = template.render(target=target)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_out)
