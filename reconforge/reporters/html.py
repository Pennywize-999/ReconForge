import os
from jinja2 import Environment, PackageLoader
from reconforge.core.models import Target

class HTMLReporter:
    def __init__(self):
        self.env = Environment(loader=PackageLoader('reconforge', 'templates'))

    def report(self, target: Target, output_file: str):
        template = self.env.get_template('report.html')
        html_content = template.render(target=target)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
