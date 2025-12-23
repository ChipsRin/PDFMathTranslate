# Extended Test Suite

Comprehensive tests that improve coverage from **31% to 42%**.

## Structure

- `unit/` - Extended unit tests for core modules
- `integration/` - Translation service integration tests (15+ services)
- `metamorphic/` - Metamorphic testing (4 MRs for PDF translation quality)
- `property_based/` - Property-based testing with Input Space Partitioning (ISP)
- `utils/` - Shared test utilities (PDFAnalyzer)

## Running Tests

```bash
# Run all extended tests
pytest test/extended/

# Run specific category
pytest test/extended/unit/
pytest test/extended/integration/
pytest test/extended/metamorphic/
pytest test/extended/property_based/

# With coverage report
pytest test/extended/ --cov=pdf2zh --cov-report=html
```

## Test Data

Test PDFs: `test/fixtures/sample_pdfs/`
Translated PDFs: `test/fixtures/translated_pdfs/` (cached to avoid repeated API calls)

## Key Improvements

**Coverage:**
- cache.py: 89% → 96% (+7%)
- config.py: 55% → 74% (+19%)
- translator.py: 49% → 72% (+23%)
- pdfinterp.py: 16% → 45% (+29%)


