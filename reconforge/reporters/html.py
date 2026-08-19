import os
from jinja2 import Environment, FileSystemLoader
from reconforge.core.models import Target

class HTMLReporter:
    def __init__(self):
        # We assume the templates dir is at ../templates relative to this file
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def report(self, target: Target, output_file: str):
        template = self.env.get_template('report.html')
        html_content = template.render(target=target)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
