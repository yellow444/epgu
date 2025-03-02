import React from 'react';

function JsonViewer({ data }) {
  return (
    <pre
      style={{
        margin: '10px',
        background: '#f4f4f4',
        padding: '10px',
        borderRadius: '5px',
      }}
    >
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

JsonViewer.propTypes = {};

JsonViewer.defaultProps = {};

export default JsonViewer;
