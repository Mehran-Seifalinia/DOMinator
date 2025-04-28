"""
HTML Parser Test Module
Unit tests for the HTML parser functionality.
"""

import unittest
from typing import List
from html_parser import ScriptExtractor, validate_html

class TestScriptExtractor(unittest.TestCase):
    """
    Test cases for the ScriptExtractor class.
    
    This class contains various test cases to verify the functionality
    of the ScriptExtractor class in different scenarios.
    """
    
    def test_valid_html_with_simple_inline_scripts(self) -> None:
        """
        Test extracting simple inline scripts from valid HTML.
        
        This test verifies that the extractor correctly identifies and
        extracts simple inline scripts from well-formed HTML.
        """
        html = """
        <html>
            <body>
                <script>console.log("test");</script>
                <script>document.write("hello");</script>
            </body>
        </html>
        """
        extractor = ScriptExtractor(html)
        scripts = extractor.get_scripts()
        self.assertEqual(sorted(scripts), sorted(['console.log("test");', 'document.write("hello");']))

    def test_html_without_scripts(self) -> None:
        """
        Test HTML with no scripts returns empty list.
        
        This test verifies that the extractor correctly handles HTML
        that contains no script tags.
        """
        html = "<html><body><p>No scripts here</p></body></html>"
        extractor = ScriptExtractor(html)
        scripts = extractor.get_scripts()
        self.assertEqual(scripts, [])

    def test_html_with_empty_script(self) -> None:
        """
        Test HTML with empty script tag returns empty list.
        
        This test verifies that the extractor correctly handles empty
        script tags.
        """
        html = "<html><body><script></script></body></html>"
        extractor = ScriptExtractor(html)
        scripts = extractor.get_scripts()
        self.assertEqual(scripts, [])

    def test_html_with_duplicate_scripts(self) -> None:
        """
        Test duplicate inline scripts are deduplicated.
        
        This test verifies that the extractor correctly handles and
        deduplicates identical script contents.
        """
        html = """
        <html>
            <body>
                <script>console.log("test");</script>
                <script>console.log("test");</script>
            </body>
        </html>
        """
        extractor = ScriptExtractor(html)
        scripts = extractor.get_scripts()
        self.assertEqual(scripts, ['console.log("test");'])
        self.assertEqual(len(scripts), 1)

    def test_html_with_external_scripts(self) -> None:
        """
        Test external scripts are ignored.
        
        This test verifies that the extractor correctly ignores
        external script references.
        """
        html = """
        <html>
            <body>
                <script src="external.js"></script>
                <script>alert("inline");</script>
            </body>
        </html>
        """
        extractor = ScriptExtractor(html)
        scripts = extractor.get_scripts()
        self.assertEqual(scripts, ['alert("inline");'])

    def test_invalid_html(self) -> None:
        """
        Test invalid HTML raises ValueError.
        
        This test verifies that the extractor correctly raises a
        ValueError for malformed HTML.
        """
        html = "<html><body><script>unclosed"
        with self.assertRaises(ValueError):
            ScriptExtractor(html)

    def test_complex_html_with_nested_scripts(self) -> None:
        """
        Test extracting scripts from complex nested HTML.
        
        This test verifies that the extractor correctly handles
        complex HTML structures with nested scripts.
        """
        html = """
        <html>
            <head>
                <script>var x = 1;</script>
            </head>
            <body>
                <div>
                    <script>document.getElementById("test").innerHTML = "nested";</script>
                </div>
                <script src="external.js"></script>
            </body>
        </html>
        """
        extractor = ScriptExtractor(html)
        scripts = extractor.get_scripts()
        self.assertEqual(sorted(scripts), sorted([
            'var x = 1;',
            'document.getElementById("test").innerHTML = "nested";'
        ]))

    def test_empty_or_invalid_input(self) -> None:
        """
        Test empty string or wrong input type raises TypeError.
        
        This test verifies that the extractor correctly handles
        invalid input types and empty strings.
        """
        with self.assertRaises(TypeError):
            ScriptExtractor("")
        with self.assertRaises(TypeError):
            ScriptExtractor(None)
        with self.assertRaises(TypeError):
            ScriptExtractor(123)

    def test_html_with_weird_formatting(self) -> None:
        """
        Test HTML with extra whitespace and odd formatting.
        
        This test verifies that the extractor correctly handles
        HTML with unusual formatting and whitespace.
        """
        html = """
        <html>
            <body>
                <script>
                    alert("weird formatting");
                </script>
                <script    >    console.log("spaces");    </script>
            </body>
        </html>
        """
        extractor = ScriptExtractor(html)
        scripts = extractor.get_scripts()
        self.assertEqual(sorted(scripts), sorted([
            'alert("weird formatting");',
            'console.log("spaces");'
        ]))

    def test_validate_html_function(self) -> None:
        """
        Test the validate_html function independently.
        
        This test verifies that the validate_html function correctly
        identifies valid and invalid HTML.
        """
        valid_html = "<html><body><p>Valid</p></body></html>"
        invalid_html = "<html><body><script>unclosed"
        self.assertTrue(validate_html(valid_html))
        self.assertFalse(validate_html(invalid_html))

if __name__ == "__main__":
    unittest.main()
