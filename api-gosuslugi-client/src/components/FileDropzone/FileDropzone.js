import React from 'react';
import { useDropzone } from 'react-dropzone';

function FileDropzone({
  onDrop, // Используем переданную функцию handleFileDrop
  files, // Получаем список файлов из App.js
  setFiles, // Функция для обновления списка файлов
  accept = '*',
  multiple = true,
  description = 'Перетащите файлы сюда или нажмите для выбора',
}) {
  const { getRootProps, getInputProps } = useDropzone({
    onDrop: (acceptedFiles) => {
      if (onDrop) {
        onDrop(acceptedFiles); // Вызываем функцию handleFileDrop
      } else {
        const updatedFiles = [...files, ...acceptedFiles];
        setFiles(updatedFiles);
      }
    },
    accept,
    multiple,
  });

  const removeFile = (index) => {
    const updatedFiles = files.filter((_, i) => i !== index);
    setFiles(updatedFiles);
  };

  const clearFiles = () => {
    setFiles([]);
  };

  return (
    <div>
      <div
        {...getRootProps()}
        style={{
          border: '2px dashed #ccc',
          padding: '20px',
          cursor: 'pointer',
          textAlign: 'center',
        }}
      >
        <input {...getInputProps()} />
        <p>{description}</p>
      </div>

      {files.length > 0 && (
        <div style={{ marginTop: '10px' }}>
          <h4>Загруженные файлы:</h4>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {files.map((file, index) => (
              <li key={index} style={{ marginBottom: '5px' }}>
                {file.name}
                <button
                  onClick={() => removeFile(index)}
                  style={{
                    marginLeft: '10px',
                    marginTop: '10px',
                    padding: '5px',
                    borderRadius: '5px',
                    border: 'none',
                    background: '#dc3545',
                    cursor: 'pointer',
                    color: '#fff',
                  }}
                >
                  X
                </button>
              </li>
            ))}
          </ul>
          <button
            style={{
              marginTop: '10px',
              padding: '5px 10px',
              borderRadius: '5px',
              border: 'none',
              background: '#dc3545',
              cursor: 'pointer',
              color: '#fff',
            }}
            onClick={clearFiles}
          >
            Очистить список файлов
          </button>
        </div>
      )}
    </div>
  );
}

export default FileDropzone;
