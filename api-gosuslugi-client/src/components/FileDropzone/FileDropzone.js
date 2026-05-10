import React from 'react';
import { useDropzone } from 'react-dropzone';
import { Button, List, Typography, Space } from 'antd';
import {
  InboxOutlined,
  DeleteOutlined,
  ClearOutlined,
  FileOutlined,
} from '@ant-design/icons';

const { Text } = Typography;

function FileDropzone({
  onDrop, // Используем переданную функцию handleFileDrop
  files, // Получаем список файлов из App.js
  setFiles, // Функция для обновления списка файлов
  accept = '*',
  multiple = true,
  description = 'Перетащите файлы сюда или нажмите для выбора',
}) {
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
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
          border: `2px dashed ${isDragActive ? '#1677ff' : '#d9d9d9'}`,
          borderRadius: 8,
          padding: '32px 20px',
          cursor: 'pointer',
          textAlign: 'center',
          background: isDragActive ? '#e6f4ff' : '#fafafa',
          transition: 'all 0.3s ease',
        }}
      >
        <input {...getInputProps()} />
        <InboxOutlined style={{ fontSize: 40, color: '#1677ff', marginBottom: 8 }} />
        <p style={{ margin: 0, color: '#595959' }}>{description}</p>
      </div>

      {files.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <List
            size="small"
            header={
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Text strong>Загруженные файлы ({files.length})</Text>
                <Button
                  danger
                  size="small"
                  icon={<ClearOutlined />}
                  onClick={clearFiles}
                >
                  Очистить все
                </Button>
              </div>
            }
            bordered
            dataSource={files}
            renderItem={(file, index) => (
              <List.Item
                actions={[
                  <Button
                    key="delete"
                    type="text"
                    danger
                    size="small"
                    icon={<DeleteOutlined />}
                    onClick={() => removeFile(index)}
                  />,
                ]}
              >
                <Space>
                  <FileOutlined style={{ color: '#1677ff' }} />
                  <Text>{file.name}</Text>
                </Space>
              </List.Item>
            )}
          />
        </div>
      )}
    </div>
  );
}

export default FileDropzone;
