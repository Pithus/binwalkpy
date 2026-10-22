use std::fs;
use std::path::PathBuf;

use binwalk::Binwalk;
use binwalk::extractors::common::ExtractionResult;
use binwalk::signatures::common::SignatureResult;

use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

// Convert Rust scan results to Python list[dict].
fn scan_to_python(
    py: Python<'_>,
    results: Vec<SignatureResult>,
) -> PyResult<Py<PyAny>> {
    let output = PyList::empty(py);

    for result in results {
        let dict = PyDict::new(py);

        dict.set_item("offset", result.offset)?;
        dict.set_item("id", result.id)?;
        dict.set_item("size", result.size)?;
        dict.set_item("name", result.name)?;
        dict.set_item("confidence", result.confidence)?;
        dict.set_item("description", result.description)?;
        dict.set_item("always_display", result.always_display)?;
        dict.set_item("extraction_declined", result.extraction_declined)?;

        output.append(dict)?;
    }

    Ok(output.into())
}

// Convert Rust extraction results to Python dict[str, dict].
fn extraction_to_python(
    py: Python<'_>,
    results: std::collections::HashMap<String, ExtractionResult>,
) -> PyResult<Py<PyAny>> {
    let output = PyDict::new(py);

    for (key, result) in results {
        let dict = PyDict::new(py);

        dict.set_item("size", result.size)?;
        dict.set_item("success", result.success)?;
        dict.set_item("extractor", result.extractor)?;
        dict.set_item("do_not_recurse", result.do_not_recurse)?;
        dict.set_item("output_directory", result.output_directory)?;

        output.set_item(key, dict)?;
    }

    Ok(output.into())
}

#[pyclass(name = "Binwalk", unsendable)]
struct PyBinwalk {
    inner: Binwalk,
    target_path: Option<PathBuf>,
}

#[pymethods]
impl PyBinwalk {
    #[new]
    #[pyo3(signature = (
        target_file_name = None,
        output_directory = None,
        include = None,
        exclude = None,
        full_search = false
    ))]
    fn new(
        target_file_name: Option<String>,
        output_directory: Option<String>,
        include: Option<Vec<String>>,
        exclude: Option<Vec<String>>,
        full_search: bool,
    ) -> PyResult<Self> {
        let target_path = target_file_name
            .as_ref()
            .map(PathBuf::from);

        let inner = Binwalk::configure(
            target_file_name,
            output_directory,
            include,
            exclude,
            None,
            full_search,
        )
        .map_err(|err| PyValueError::new_err(err.message))?;

        Ok(Self {
            inner,
            target_path,
        })
    }

    #[getter]
    fn base_target_file(&self) -> String {
        self.inner.base_target_file.clone()
    }

    #[getter]
    fn base_output_directory(&self) -> String {
        self.inner.base_output_directory.clone()
    }

    #[getter]
    fn signature_count(&self) -> usize {
        self.inner.signature_count
    }

    #[getter]
    fn pattern_count(&self) -> usize {
        self.inner.pattern_count
    }

    fn scan(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<Py<PyAny>> {
        let results = self.inner.scan(&data);
        scan_to_python(py, results)
    }

    fn extract(&self, py: Python<'_>, data: Vec<u8>, file_name: String) -> PyResult<Py<PyAny>> {
        let file_map = self.inner.scan(&data);
        let results = self.inner.extract(&data, file_name, &file_map);

        extraction_to_python(py, results)
    }

    fn scan_file(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let path = self.target_path.as_ref().ok_or_else(|| {
            PyValueError::new_err(
                "No target_file_name was specified during configuration"
            )
        })?;

        let data = fs::read(path).map_err(|err| {
            PyOSError::new_err(format!(
                "Failed to read {}: {}",
                path.display(),
                err
            ))
        })?;

        let results = self.inner.scan(&data);
        scan_to_python(py, results)
    }

    fn extract_file(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let path = self.target_path.as_ref().ok_or_else(|| {
            PyValueError::new_err(
                "No target_file_name was specified during configuration"
            )
        })?;

        let data = fs::read(path).map_err(|err| {
            PyOSError::new_err(format!(
                "Failed to read {}: {}",
                path.display(),
                err
            ))
        })?;

        let file_map = self.inner.scan(&data);
        let results = self.inner.extract(
            &data,
            self.inner.base_target_file.clone(),
            &file_map,
        );

        extraction_to_python(py, results)
    }
}

#[pymodule]
fn binwalkpy(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBinwalk>()?;
    Ok(())
}