import React, { useState, useEffect, useRef, useCallback } from 'react';
import DatePicker from 'react-datepicker';
import 'react-datepicker/dist/react-datepicker.css';
import axios from 'axios';
import moment from 'moment-timezone';
import xmlFormatter from 'xml-formatter';
import AceEditor from 'react-ace';
import 'ace-builds/src-noconflict/mode-xml';
import 'ace-builds/src-noconflict/theme-github';
import 'ace-builds/src-noconflict/worker-xml';
import 'ace-builds/webpack-resolver';
import FileDropzone from './components/FileDropzone/FileDropzone';
import logo from './logo.gosuslugi.svg';
import { jwtDecode } from 'jwt-decode';
import { openDB } from 'idb';

const BACKEND_URL =
  process.env.REACT_APP_BACKEND_URL || 'http://192.168.50.100:5000/api';

// Создаём или открываем IndexedDB базу данных
const dbPromise = openDB('files-db', 1, {
  upgrade(db) {
    // Создаем хранилище с ключом 'name'
    db.createObjectStore('files', { keyPath: 'name' });
  },
});
function dataURLtoBlob(dataurl) {
  const [header, base64Data] = dataurl.split(',');
  const mimeMatch = header.match(/:(.*?);/);
  const mime = mimeMatch ? mimeMatch[1] : 'application/octet-stream';
  const byteString = atob(base64Data);
  const ab = new Uint8Array(byteString.length);
  for (let i = 0; i < byteString.length; i++) {
    ab[i] = byteString.charCodeAt(i);
  }
  return new Blob([ab], { type: mime });
}

function App() {
  // Основные рефы и состояния
  const isDragging = useRef(false);
  const [allowBtn, setAllowBtn] = useState(true);
  const [leftWidth, setLeftWidth] = useState(50);
  const [currentTab, setCurrentTab] = useState(
    sessionStorage.getItem('currentTab') || 'main'
  );

  const [selectItem, setSelectItem] = useState(() => {
    const saved = localStorage.getItem('selectItem');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return [];
      }
    }
    return [];
  });
  // Сертификаты, токен, API key и OrderID
  const cancelTokenSourceRef = useRef(null);
  const requestIdRef = useRef(0);
  const [token, setToken] = useState(sessionStorage.getItem('token') || '');
  const [apiKey, setApiKey] = useState('');
  const [certificates, setCertificates] = useState([]);
  const [selectedCertId, setSelectedCertId] = useState('0');
  const [orderId, setOrderId] = useState(
    sessionStorage.getItem('orderId') || ''
  );
  const [status, setStatus] = useState('');

  // Файлы для загрузки и размер будущего ZIP
  const [files, setFiles] = useState([]);
  const [filesList, setFilesList] = useState(() => {
    const saved = localStorage.getItem('filesList');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error('Ошибка восстановления списка файлов', e);
        return [];
      }
    }
    return [];
  });
  const [zipSize, setZipSize] = useState(0); // в байтах

  // XML документы (по умолчанию два: req и piev_epgu)
  const [xmlDocuments, setXmlDocuments] = useState(() => {
    const saved = localStorage.getItem('xmlDocuments');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error('Ошибка восстановления XML файлов', e);
        return [
          { name: 'req', content: '' },
          { name: 'piev_epgu', content: '' },
        ];
      }
    }
    return [
      { name: 'req', content: '' },
      { name: 'piev_epgu', content: '' },
    ];
  });

  const [selectedXmlIndex, setSelectedXmlIndex] = useState(0);

  // Выбор вида услуги (от которого меняются XML шаблоны)
  const [selectedService, setSelectedService] = useState('');
  const [serviceOptions, setServiceOptions] = useState([]);
  // Пагинация и дата обновления запросов
  const [updatedAfter, setUpdatedAfter] = useState(() => {
    const saved = localStorage.getItem('updatedAfter');
    if (saved) {
      try {
        return new Date(JSON.parse(saved));
      } catch (e) {
        return new Date();
      }
    }
    return new Date();
  });

  const [pageNum, setPageNum] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [totalRecords, setTotalRecords] = useState(50);
  const [paginatedData, setPaginatedData] = useState(() => {
    const saved = localStorage.getItem('paginatedData');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return [];
      }
    }
    return [];
  });
  const [responseData, setResponseData] = useState(() => {
    const saved = localStorage.getItem('responseData');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return;
      }
    }
    return;
  });
  const [responseTable, setResponseTable] = useState(() => {
    const saved = localStorage.getItem('responseTable');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return;
      }
    }
    return;
  });
  const [responseStatusOrder, setResponseStatusOrder] = useState(() => {
    const saved = localStorage.getItem('responseStatusOrder');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return;
      }
    }
    return;
  });
  const [responseStatusItem, setResponseStatusItem] = useState(() => {
    const saved = localStorage.getItem('responseStatusItem');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return;
      }
    }
    return;
  });
  const [isFileAvailable, setIsFileAvailable] = useState(false);
  const [isFileItemAvailable, setIsFileItemAvailable] = useState(false);
  const [copyButtonIndex, setCopyButtonIndex] = useState(null);

  // Axios-инстанс с токеном
  const api = axios.create({
    baseURL: BACKEND_URL,
    headers: { Authorization: `Bearer ${token}` },
  });

  // Функции управления токеном
  const updateToken = (newToken) => {
    sessionStorage.setItem('token', newToken);
    setToken(newToken);
  };
  const isTokenExpired = (token) => {
    try {
      const { exp } = jwtDecode(token);
      return Date.now() >= exp * 1000;
    } catch (e) {
      return true;
    }
  };
  const fetchAccessToken = async () => {
    try {
      const res = await api.post('/accessTkn_esia', { api_key: apiKey });
      const newToken = res.data.accessTkn || '';
      updateToken(newToken);
      setStatus('Токен успешно получен.');
    } catch (e) {
      setStatus('Ошибка получения токена.');
    }
  };
  const handleLogout = () => {
    sessionStorage.removeItem('token');
    setToken('');
    setStatus('Токен удалён.');
  };
  const refreshToken = async () => {
    try {
      const res = await api.post('/accessTkn_esia', { api_key: apiKey });
      const newToken = res.data.accessTkn || '';
      updateToken(newToken);
      setStatus('Токен обновлён.');
    } catch (e) {
      setStatus('Ошибка обновления токена.');
    }
  };
  useEffect(() => {
    const interval = setInterval(
      () => {
        if (token && isTokenExpired(token)) {
          refreshToken();
        }
      },
      5 * 60 * 1000
    );
    return () => clearInterval(interval);
  }, [token]);

  useEffect(() => {
    localStorage.setItem('xmlDocuments', JSON.stringify(xmlDocuments));
  }, [xmlDocuments]);

  useEffect(() => {
    localStorage.setItem(
      'responseStatusItem',
      JSON.stringify(responseStatusItem)
    );
  }, [responseStatusItem]);

  useEffect(() => {
    localStorage.setItem('paginatedData', JSON.stringify(paginatedData));
  }, [paginatedData]);

  useEffect(() => {
    localStorage.setItem('selectItem', JSON.stringify(selectItem));
  }, [selectItem]);

  useEffect(() => {
    localStorage.setItem('responseData', JSON.stringify(responseData));
  }, [responseData]);

  useEffect(() => {
    localStorage.setItem(
      'responseStatusOrder',
      JSON.stringify(responseStatusOrder)
    );
  }, [responseStatusOrder]);

  useEffect(() => {
    localStorage.setItem('responseTable', JSON.stringify(responseTable));
  }, [responseTable]);

  useEffect(() => {
    localStorage.setItem(
      'updatedAfter',
      JSON.stringify(updatedAfter.toISOString())
    );
  }, [updatedAfter]);

  // XML функции

  const parseXml = (xmlString) =>
    new DOMParser().parseFromString(xmlString, 'application/xml');
  const serializeXml = (dom) => new XMLSerializer().serializeToString(dom);
  const prettifyXml = () => {
    if (!xmlDocuments[selectedXmlIndex]) {
      setStatus('Нет выбранного XML документа.');
      return;
    }
    try {
      const formatted = xmlFormatter(xmlDocuments[selectedXmlIndex].content, {
        indentation: '  ',
        collapseContent: true,
      });
      const updated = [...xmlDocuments];
      updated[selectedXmlIndex].content = formatted;
      setXmlDocuments(updated);
      setStatus(
        `XML документ "${updated[selectedXmlIndex].name}" отформатирован.`
      );
    } catch (e) {
      setStatus('Ошибка форматирования XML.');
    }
  };
  const updateXmlContent = (newContent) => {
    const updated = [...xmlDocuments];
    updated[selectedXmlIndex].content = newContent;
    setXmlDocuments(updated);
  };
  const saveXmlFile = async () => {
    const currentDoc = xmlDocuments[selectedXmlIndex];
    if (!currentDoc) {
      setStatus('Нет выбранного XML документа для сохранения.');
      return;
    }
    try {
      const fileHandle = await window.showSaveFilePicker({
        suggestedName: `${currentDoc.name}.xml`,
        types: [
          {
            description: 'XML Files',
            accept: { 'application/xml': ['.xml'] },
          },
        ],
      });
      const writable = await fileHandle.createWritable();
      await writable.write(currentDoc.content);
      await writable.close();
      setStatus(`XML документ "${currentDoc.name}" успешно сохранён.`);
    } catch (e) {
      setStatus('Сохранение отменено или произошла ошибка.');
    }
  };
  const loadXmlFromFile = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      const updated = [...xmlDocuments];
      updated[selectedXmlIndex].content = content;
      setXmlDocuments(updated);
      setStatus(
        `XML файл загружен в документ "${updated[selectedXmlIndex].name}".`
      );
    };
    reader.readAsText(file);
  };

  // File drop handler
  const handleFileDrop = (acceptedFiles) => {
    const newFiles = acceptedFiles.map((file) =>
      file instanceof File
        ? file
        : new File([file], file.name, {
            type: file.type || 'application/octet-stream',
            lastModified: file.lastModified || Date.now(),
          })
    );
    setFiles([...files, ...newFiles]);
  };

  // Расчёт размера ZIP-архива через API /api/zipsize
  const calculateZipSize = async () => {
    if (files.length === 0) {
      setZipSize(0);
      return;
    }

    // Если предыдущий запрос выполняется, отменяем его
    if (cancelTokenSourceRef.current) {
      cancelTokenSourceRef.current.cancel(
        'Предыдущий запрос отменен, т.к. начат новый.'
      );
    }
    requestIdRef.current += 1;
    const currentRequestId = requestIdRef.current;

    // Создаем новый CancelToken для текущего запроса
    cancelTokenSourceRef.current = axios.CancelToken.source();

    setAllowBtn(false);
    await new Promise((resolve) => setTimeout(resolve, 0));

    const formData = new FormData();
    files.forEach((file) => formData.append('files_upload', file));

    try {
      const res = await api.post('/zipsize', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        cancelToken: cancelTokenSourceRef.current.token,
      });
      setZipSize(res.data.zip_size);
    } catch (e) {
      if (!axios.isCancel(e)) {
        console.error('Ошибка расчёта размера архива', e);
      }
    }
    if (currentRequestId === requestIdRef.current) {
      setAllowBtn(true);
    }
  };

  // Общий обработчик ошибок
  const handleError = (e) => {
    let errMsg = 'Ошибка подключения к API.';
    if (e.response) {
      errMsg = `Ошибка: ${e.response.status} - ${e.response.data.detail || ''}`;
    }
    setStatus(errMsg);
    console.error(errMsg);
  };

  // API: проверка статуса
  const checkAPI = async () => {
    try {
      const res = await api.get('/status');
      setStatus('API доступно.');
      setResponseData(res.data);
    } catch (e) {
      handleError(e);
    }
  };
  // проверка типа файлп
  const checkFileType = async (simple_type_name) => {
    try {
      const res = await api.get(`${BACKEND_URL}/xsd`, {
        params: { simple_type_name },
      });
      return res.data;
    } catch (e) {
      handleError(e);
      return [];
    }
  };

  const getValueByFileExtension = (fileName, dsContentTypeValueList) => {
    // Извлекаем расширение файла и приводим его к нижнему регистру
    const extension = fileName.split('.').pop().toLowerCase();

    // Ищем объект, у которого documentation соответствует расширению
    const found = dsContentTypeValueList.find(
      (item) =>
        item.documentation && item.documentation.toLowerCase() === extension
    );

    return found
      ? found.value
      : dsContentTypeValueList.find(
          (item) =>
            item.documentation && item.documentation.toLowerCase() === '*'
        ).value;
  };
  const updateXmlDocumentsWithFiles = async () => {
    const namespace = 'http://www.fssprus.ru/namespace/incoming/2019/1';

    // 1. Обновляем общие поля во всех XML-документах:
    const updatedCommonDocs = xmlDocuments.map((doc) => {
      const dom = parseXml(doc.content);

      // Обновляем поля ExternalKey и OrderId
      let elems = dom.getElementsByTagName('fssp:ExternalKey');
      for (let elem of elems) {
        elem.textContent = orderId;
      }
      elems = dom.getElementsByTagName('fssp:OrderId');
      for (let elem of elems) {
        elem.textContent = orderId;
      }

      const today = new Date();
      // Обновляем дату документа
      elems = dom.getElementsByTagName('fssp:DocDate');
      for (let elem of elems) {
        elem.textContent = moment(today).format('YYYY-MM-DD');
      }
      elems = dom.getElementsByTagName('fssp:StatementDate');
      for (let elem of elems) {
        elem.textContent = moment(today).format('YYYY-MM-DD');
      }
      elems = dom.getElementsByTagName('fssp:Date');
      for (let elem of elems) {
        elem.textContent = moment()
          .tz('Europe/Moscow')
          .format('YYYY-MM-DDTHH:mmssZ');
      }
      const updatedXml = serializeXml(dom);
      return { ...doc, content: updatedXml };
    });
    // Создаем изменяемую копию для последующих обновлений
    let updatedDocs = [...updatedCommonDocs];

    // 2. Обновляем документ req (например, req.xml):
    const reqIndex = updatedDocs.findIndex((doc) => doc.name === 'req');
    if (reqIndex !== -1) {
      const domReq = parseXml(updatedDocs[reqIndex].content);
      let epguRequestElem = domReq.getElementsByTagName('fssp:EPGURequest')[0];
      if (!epguRequestElem) {
        epguRequestElem = domReq.documentElement;
        if (!epguRequestElem) {
          epguRequestElem = domReq.createElementNS(
            namespace,
            'fssp:EPGURequest'
          );
          domReq.appendChild(epguRequestElem);
        }
      }
      // Обновляем <fssp:ServiceCode>
      const serviceCodeElem =
        epguRequestElem.getElementsByTagName('fssp:ServiceCode')[0];
      if (serviceCodeElem) {
        serviceCodeElem.textContent = selectedService;
      }
      // Обновляем <fssp:TargetCode>
      const targetCodeElem =
        epguRequestElem.getElementsByTagName('fssp:TargetCode')[0];
      if (targetCodeElem) {
        const targetCode = serviceOptions.find(
          (e) => e.serviceCode === selectedService
        )?.targetCode;
        targetCodeElem.textContent = targetCode;
      }
      updatedDocs[reqIndex] = {
        ...updatedDocs[reqIndex],
        content: serializeXml(domReq),
      };
    }

    // 3. Обновляем документ piev_epgu (например, piev_epgu.xml) – секция файлов:
    const pievIndex = updatedDocs.findIndex((doc) => doc.name === 'piev_epgu');
    if (pievIndex !== -1) {
      const domPiev = parseXml(updatedDocs[pievIndex].content);
      let requestElem = domPiev.getElementsByTagName('fssp:IRequest')[0];
      if (!requestElem) {
        requestElem = domPiev.documentElement;
        if (!requestElem) {
          requestElem = domPiev.createElementNS(namespace, 'fssp:IRequest');
          domPiev.appendChild(requestElem);
        }
      }
      // Получаем список имён файлов из ранее сохраненного массива filesList
      const filesListNames = filesList.map((file) => file.name);

      // Удаляем из секции <fssp:IRequest> только те <fssp:Attachment>,
      // которые относятся к файлам из File Upload (т.е. их fssp:DsFileName совпадает с именем)
      const existingAttachments = Array.from(
        requestElem.getElementsByTagName('fssp:Attachment')
      );
      existingAttachments.forEach((attachment) => {
        const dsFileNameElem =
          attachment.getElementsByTagName('fssp:DsFileName')[0];
        if (
          dsFileNameElem &&
          filesListNames.includes(dsFileNameElem.textContent)
        ) {
          requestElem.removeChild(attachment);
        }
      });

      // Обновляем список файлов: сохраняем новые имена из files
      const newFilesList = files.map((file) => ({ name: file.name }));
      setFilesList(newFilesList);

      // Добавляем новые <fssp:Attachment> для каждого файла из File Upload
      for (const file of files) {
        const attachmentElem = domPiev.createElementNS(
          namespace,
          'fssp:Attachment'
        );
        const dsFileNameElem = domPiev.createElementNS(
          namespace,
          'fssp:DsFileName'
        );
        const dsDataDigest = domPiev.createElementNS(
          namespace,
          'fssp:DsDataDigest'
        );
        const dsContentType = domPiev.createElementNS(
          namespace,
          'fssp:DsContentType'
        );

        // Получаем значение content type для файла
        const dsContentTypeValueList = await checkFileType('DContentTypeType');
        const dsContentTypeValue = getValueByFileExtension(
          file.name,
          dsContentTypeValueList
        );
        dsFileNameElem.textContent = file.name;
        dsContentType.textContent = dsContentTypeValue;
        dsDataDigest.textContent = 'MA==';

        attachmentElem.appendChild(dsFileNameElem);
        attachmentElem.appendChild(dsDataDigest);
        attachmentElem.appendChild(dsContentType);

        requestElem.appendChild(attachmentElem);
      }

      updatedDocs[pievIndex] = {
        ...updatedDocs[pievIndex],
        content: serializeXml(domPiev),
      };
    }

    // Обновляем состояние XML-документов и статус
    setXmlDocuments(updatedDocs);
    setStatus('XML документы обновлены.');
  };

  // При нажатии на кнопку "Заполнить XML"
  const handleFillXml = () => {
    updateXmlDocumentsWithFiles();
  };

  const reserveOrder = async () => {
    try {
      const res = await api.post(`${BACKEND_URL}/order`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setOrderId(res.data.orderId);
      setResponseData('Новый запроса успешно зарезервирован.');
    } catch (error) {
      handleError(error);
    }
  };

  // Создание нового запроса. Если файлы добавлены, перед отправкой заполняем piev_epgu.xml
  const newOrder = async () => {
    try {
      const formData = new FormData();
      files.forEach((file) => formData.append('files_upload', file));
      xmlDocuments.forEach((doc) => {
        const blob = new Blob([doc.content], { type: 'application/xml' });
        formData.append('files_upload', blob, `${doc.name}.xml`);
      });
      formData.append(
        'meta',
        JSON.stringify({
          region: serviceOptions.find((e) => e.serviceCode === selectedService)
            ?.region,
          serviceCode: serviceOptions.find(
            (e) => e.serviceCode === selectedService
          )?.eServiceCode,
          targetCode: serviceOptions.find(
            (e) => e.serviceCode === selectedService
          )?.serviceTargetCode,
        })
      );
      const res = await api.post('/push', formData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setOrderId(res.data.orderId);
      setResponseData('Запрос создан.');
    } catch (e) {
      console.error('Ошибка создания запроса:', e);
      setStatus('Ошибка создания запроса.');
    }
  };

  // Создание расширенного запроса (chunked)
  const createOrderExtended = async () => {
    try {
      const formData = new FormData();
      xmlDocuments.forEach((doc) => {
        const blob = new Blob([doc.content], { type: 'application/xml' });
        formData.append('files_upload', blob, `${doc.name}.xml`);
      });
      files.forEach((file) => formData.append('files_upload', file));
      formData.append(
        'meta',
        JSON.stringify({
          region: serviceOptions.find((e) => e.serviceCode === selectedService)
            ?.region,
          serviceCode: serviceOptions.find(
            (e) => e.serviceCode === selectedService
          )?.eServiceCode,
          targetCode: serviceOptions.find(
            (e) => e.serviceCode === selectedService
          )?.serviceTargetCode,
        })
      );
      formData.append('chunks', '1');
      formData.append('chunk', '0');
      formData.append('orderId', orderId);
      const res = await api.post('/push/chunked', formData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setOrderId(res.data.orderId);
      setResponseData('Расширенный запрос создан.');
    } catch (e) {
      console.error('Ошибка создания расширенного запроса:', e);
      setStatus('Ошибка создания расширенного запроса.');
    }
  };

  // Получение деталей запроса
  const getOrderDetails = async (id) => {
    const payload = {
      region: serviceOptions.find((e) => e.serviceCode === selectedService)
        ?.region,
      serviceCode: serviceOptions.find((e) => e.serviceCode === selectedService)
        ?.eServiceCode,
      targetCode: serviceOptions.find((e) => e.serviceCode === selectedService)
        ?.serviceTargetCode,
    };
    return await api.post(`/order/${id}`, payload, {
      headers: { Authorization: `Bearer ${token}` },
    });
  };
  const checkOrderDetailsMain = async (id) => {
    try {
      const res = await getOrderDetails(id);
      const { message, fileDetails, orderDetails } = res.data;
      setStatus(`Получен статус для ${id} ${message}`);
      setResponseStatusOrder(orderDetails);
      setIsFileAvailable(!!fileDetails);
    } catch (e) {
      handleError(e);
      setResponseData('');
      setIsFileAvailable(false);
    }
  };
  const checkOrderDetailsItem = async (id) => {
    try {
      setSelectItem(id);
      const res = await getOrderDetails(id);
      const { message, fileDetails, orderDetails } = res.data;
      setStatus(`Получен статус для ${id} ${message}`);
      setResponseStatusItem(orderDetails);
      setIsFileItemAvailable(!!fileDetails);
    } catch (e) {
      handleError(e);
      setResponseStatusItem();
      setIsFileItemAvailable(false);
    }
  };
  const downloadOrderFile = async (fileOrderId) => {
    try {
      const payload = {
        region: serviceOptions.find((e) => e.serviceCode === selectedService)
          ?.region,
        serviceCode: serviceOptions.find(
          (e) => e.serviceCode === selectedService
        )?.eServiceCode,
        targetCode: serviceOptions.find(
          (e) => e.serviceCode === selectedService
        )?.serviceTargetCode,
      };
      const res = await api.post(`/order/${fileOrderId}`, payload, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const { message, fileDetails } = res.data;
      setStatus(message);
      if (!fileDetails) return;
      fileDetails.forEach(async (file) => {
        const { objectId, objectType, mnemonic, eserviceCode } = file;
        const downloadRes = await api.post(
          `/download_file/${objectId}/${objectType}`,
          null,
          {
            headers: { Authorization: `Bearer ${token}` },
            params: { mnemonic, eserviceCode },
            responseType: 'blob',
          }
        );
        const disposition = downloadRes.headers['content-disposition'];
        const fileNameMatch =
          disposition && disposition.match(/filename="?(.+?)"?(;|$)/);
        const fileName = fileNameMatch
          ? fileNameMatch[1]
          : 'downloaded_file.zip';
        const blobUrl = window.URL.createObjectURL(
          new Blob([downloadRes.data])
        );
        const link = document.createElement('a');
        link.href = blobUrl;
        link.setAttribute('download', decodeURIComponent(fileName));
        document.body.appendChild(link);
        link.click();
        link.remove();
      });
    } catch (e) {
      handleError(e);
    }
  };
  const cancelOrder = async () => {
    try {
      const payload = {
        region: serviceOptions.find((e) => e.serviceCode === selectedService)
          ?.region,
        serviceCode: serviceOptions.find(
          (e) => e.serviceCode === selectedService
        )?.eServiceCode,
        targetCode: serviceOptions.find(
          (e) => e.serviceCode === selectedService
        )?.serviceTargetCode,
      };
      const res = await api.post(`/order/${orderId}/cancel`, payload, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setStatus(res.data.message);
      setResponseData(res.data.orderDetails);
    } catch (e) {
      handleError(e);
    }
  };

  const fetchUpdatedOrders = async () => {
    try {
      setSelectItem();
      // setIsFileAvailable(false);
      setIsFileItemAvailable(false);
      setStatus();
      setResponseStatusItem();
      setResponseTable();
      const params = {
        pageNum,
        pageSize: totalRecords,
        updatedAfter: moment(updatedAfter).format('YYYY-MM-DDTHH:mm:ss.SSS'),
      };
      const res = await api.get('/getUpdatedAfter', {
        headers: { Authorization: `Bearer ${token}` },
        params,
      });
      setResponseTable(res?.data?.content);
    } catch (e) {
      if (e.response) {
        console.error('Ошибка получения запросов:', e.response.data);
        setStatus(`Ошибка: ${e.response.data.detail || 'Неизвестная ошибка'}`);
      } else {
        setStatus('Ошибка подключения к серверу.');
      }
    }
  };
  useEffect(() => {
    if (responseData?.content) {
      const start = pageNum * pageSize;
      const end = start + pageSize;
      setPaginatedData(responseData.content.slice(start, end));
    }
  }, [responseData, pageNum, pageSize]);

  useEffect(() => {
    if (files.length !== 0) {
      // Функция для чтения содержимого файла в формате DataURL
      // Функция для чтения содержимого файла в формате DataURL
      const readFileContent = (file) => {
        return new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result);
          reader.onerror = reject;
          reader.readAsDataURL(file);
        });
      };

      // Асинхронно читаем содержимое каждого файла и сохраняем его вместе с метаданными в IndexedDB
      Promise.all(
        files.map(async (file) => {
          const content = await readFileContent(file);
          return {
            name: file.name,
            type: file.type,
            lastModified: file.lastModified,
            content, // содержимое файла в виде DataURL
          };
        })
      )
        .then(async (fileData) => {
          const db = await dbPromise;
          const tx = db.transaction('files', 'readwrite');
          for (const file of fileData) {
            await tx.store.put(file);
          }
          await tx.done;
        })
        .catch((error) => {
          console.error('Ошибка при чтении файлов:', error);
        });
    }

    calculateZipSize();
  }, [files]);

  useEffect(() => {
    localStorage.setItem('filesList', JSON.stringify(filesList));
  }, [filesList]);
  useEffect(() => {
    sessionStorage.setItem('currentTab', currentTab);
  }, [currentTab]);
  useEffect(() => {
    sessionStorage.setItem('orderId', orderId);
  }, [orderId]);

  // При изменении orderId обновляем некоторые поля XML (например, fssp:ExternalKey, fssp:OrderId и даты)
  useEffect(() => {
    if (!orderId) return;
    updateXmlDocumentsWithFiles();
    setStatus('Поля XML, связанные с OrderId, обновлены.');
  }, [orderId]);

  // Копирование в буфер обмена
  const copyToClipboard = (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text);
    } else {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.top = '-9999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
      } catch (e) {
        console.error('Ошибка копирования:', e);
      }
      document.body.removeChild(textArea);
    }
  };

  // Обработка изменения ширины таблицы (пагинация)
  const handleMouseDown = (e) => {
    e.preventDefault();
    isDragging.current = true;
  };
  const handleMouseMove = (e) => {
    if (!isDragging.current) return;
    const newWidth = (e.clientX / window.innerWidth) * 100;
    if (newWidth < 10) setLeftWidth(10);
    else if (newWidth > 90) setLeftWidth(90);
    else setLeftWidth(newWidth);
  };
  const handleMouseUp = () => {
    isDragging.current = false;
  };
  // Выбор сертификата
  const setCurrentCertificate = async (certId) => {
    try {
      await api.post('/set_current_certificate', { cert_id: certId });
      setSelectedCertId(certId);
      setStatus(`Сертификат ${certId} выбран.`);
    } catch (e) {
      setStatus('Ошибка установки сертификата.');
    }
  };

  const updateXmlDocuments = useCallback((service, force = false) => {
    if (!service) return;
    axios
      .get(`${BACKEND_URL}/xml`, { params: { service } })
      .then((response) => {
        const { req, piev_epgu } = response.data;
        const saved = localStorage.getItem('xmlDocuments');
        if (force || !saved) {
          setXmlDocuments([
            { name: 'req', content: req },
            { name: 'piev_epgu', content: piev_epgu },
          ]);
          setStatus('Получены XML с сервера');
        } else {
          setStatus('Используеться востановленный XML');
        }
      })
      .catch((error) => {
        console.error('Ошибка получения XML', error);
        setStatus('Ошибка получения XML с сервера');
      });
  }, []);
  // При выборе вида услуги меняем XML шаблоны
  useEffect(() => {
    const updateChain = async () => {
      // Сначала обновляем общие данные через updateXmlDocuments
      await updateXmlDocuments(selectedService, true);
      // Затем обновляем секцию файлов
      await updateXmlDocumentsWithFiles();
    };

    updateChain();
  }, [selectedService, updateXmlDocuments, updateXmlDocuments]);

  // При монтировании: получаем сертификаты
  useEffect(() => {
    axios
      .get(`${BACKEND_URL}/services`)
      .then((response) => {
        setServiceOptions(response.data);
        if (response.data.length > 0) {
          setSelectedService(response.data[0].serviceCode);
        }
      })
      .catch((error) => {
        console.error('Ошибка получения услуг', error);
      });
    const fetchCertificates = async () => {
      try {
        const res = await api.post('/get_certificates');
        if (res.data && res.data.length > 0) {
          setCertificates(res.data);
          setSelectedCertId(res.data[0].id);
        } else {
          setStatus('Нет доступных сертификатов.');
        }
      } catch (e) {
        setStatus('Ошибка загрузки сертификатов.');
      }
    };
    fetchCertificates();
    async function loadFiles() {
      const db = await dbPromise;
      const storedFiles = await db.getAll('files');
      const restoredFiles = storedFiles.map((file) => {
        const blob = dataURLtoBlob(file.content);
        return new File([blob], file.name, {
          type: file.type || 'application/octet-stream',
          lastModified: file.lastModified || Date.now(),
        });
      });
      setFiles(restoredFiles);
    }

    loadFiles().catch((error) => {
      console.error('Ошибка восстановления файлов из IndexedDB', error);
    });
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  return (
    <>
      <div
        style={{
          background: '#f0f4f8',
          minHeight: '100vh',
          padding: '20px',
          fontFamily: 'Arial, sans-serif',
        }}
      >
        <div
          style={{
            padding: '20px',
            // left: 0,
            // top:0,
            // position: 'fixed',
            // zIndex: 99999,
            // width: '100%',
          }}
        >
          <div
            style={{
              padding: '10px',
            }}
          >
            {/* Заголовок и навигация */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '20px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <img
                  src={logo}
                  alt="Логотип"
                  style={{ marginRight: '10px', height: '50px' }}
                />
                <h1 style={{ margin: 0 }}>API Client</h1>
              </div>
              <div>
                <button
                  onClick={() => setCurrentTab('main')}
                  style={{
                    marginRight: '10px',
                    padding: '10px 20px',
                    border: 'none',
                    borderRadius: '5px',
                    backgroundColor: currentTab === 'main' ? '#007bff' : '#ccc',
                    color: 'white',
                    cursor: 'pointer',
                  }}
                >
                  Главная
                </button>
                <button
                  onClick={() => setCurrentTab('xml')}
                  style={{
                    marginRight: '10px',
                    padding: '10px 20px',
                    border: 'none',
                    borderRadius: '5px',
                    backgroundColor: currentTab === 'xml' ? '#007bff' : '#ccc',
                    color: 'white',
                    cursor: 'pointer',
                  }}
                >
                  Редактор XML
                </button>
                <button
                  onClick={() => setCurrentTab('requests')}
                  style={{
                    padding: '10px 20px',
                    border: 'none',
                    borderRadius: '5px',
                    backgroundColor:
                      currentTab === 'requests' ? '#007bff' : '#ccc',
                    color: 'white',
                    cursor: 'pointer',
                  }}
                >
                  Запросы
                </button>
              </div>
            </div>
            {/* Блок статуса */}
            <div
              style={{
                flex: 1,
                gap: '20px',
                marginBottom: '00px',
                padding: '20px',
                background: '#fff',
                borderRadius: '8px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <h2 style={{ margin: '0 10px 0 0' }}>Статус</h2>
                <button
                  onClick={checkAPI}
                  style={{
                    padding: '5px 10px',
                    borderRadius: '5px',
                    border: 'none',
                    background: '#6f42c1',
                    color: '#fff',
                    cursor: 'pointer',
                    marginRight: '10px',
                  }}
                >
                  Проверить API Client
                </button>
                <p style={{ margin: 10, padding: '10px' }}>{status}</p>
              </div>
              <div
                style={{
                  background: '#f4f4f4',
                  padding: '10px',
                  borderRadius: '5px',
                  position: 'relative',
                }}
                onMouseEnter={() => setCopyButtonIndex(2)}
                onMouseLeave={() => setCopyButtonIndex(null)}
              >
                <pre style={{ margin: 10 }}>
                  {responseData ? JSON.stringify(responseData, null, 2) : ''}
                </pre>
                {copyButtonIndex === 2 && (
                  <button
                    onClick={() =>
                      copyToClipboard(
                        responseData
                          ? JSON.stringify(responseData, null, 2)
                          : ''
                      )
                    }
                    style={{
                      position: 'absolute',
                      top: '10px',
                      right: '10px',
                      background: '#007bff',
                      color: '#fff',
                      border: 'none',
                      borderRadius: '5px',
                      padding: '5px 10px',
                      cursor: 'pointer',
                    }}
                  >
                    Копировать
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
        {/* Основная вкладка */}
        <div
          style={{
            // marginTop: '40px', // отступ равный высоте фиксированного блока
            padding: '20px',
          }}
        >
          {currentTab === 'main' && (
            <div style={{ padding: '10px' }}>
              {/* Блок сертификатов и токена */}
              <div
                style={{
                  flex: 1,
                  gap: '20px',
                  marginBottom: '20px',
                  padding: '20px',
                  background: '#fff',
                  borderRadius: '8px',
                  boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
                }}
              >
                <div style={{ flex: 1 }}>
                  <h2>Сертификаты и токен</h2>
                  <div style={{ marginBottom: '10px' }}>
                    <label style={{ marginRight: '10px' }}>
                      Выберите сертификат:
                    </label>
                    <select
                      value={selectedCertId}
                      onChange={(e) => setCurrentCertificate(e.target.value)}
                      style={{ padding: '5px', borderRadius: '5px' }}
                    >
                      {certificates.map((cert) => (
                        <option key={cert.id} value={cert.id}>
                          {cert.subject} (Valid: {cert.valid_from} -{' '}
                          {cert.valid_to})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <input
                      type="text"
                      placeholder="Введите API key"
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      style={{ padding: '5px', marginRight: '10px' }}
                    />
                    <button
                      onClick={fetchAccessToken}
                      style={{
                        padding: '5px 10px',
                        borderRadius: '5px',
                        border: 'none',
                        background: '#28a745',
                        color: '#fff',
                        cursor: 'pointer',
                      }}
                    >
                      Получить токен
                    </button>
                    <button
                      onClick={handleLogout}
                      style={{
                        padding: '5px 10px',
                        borderRadius: '5px',
                        border: 'none',
                        background: '#dc3545',
                        color: '#fff',
                        cursor: 'pointer',
                        marginLeft: '10px',
                      }}
                    >
                      Удалить токен
                    </button>
                  </div>
                  <div
                    style={{
                      background: '#f4f4f4',
                      padding: '10px',
                      borderRadius: '5px',
                      position: 'relative',
                      marginBottom: '10px',
                    }}
                    onMouseEnter={() => setCopyButtonIndex(1)}
                    onMouseLeave={() => setCopyButtonIndex(null)}
                  >
                    <pre
                      style={{
                        margin: 0,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        maxWidth: '100%',
                      }}
                    >
                      {token}
                    </pre>
                    {copyButtonIndex === 1 && (
                      <button
                        onClick={() => copyToClipboard(token)}
                        style={{
                          position: 'absolute',
                          top: '10px',
                          right: '10px',
                          background: '#007bff',
                          color: '#fff',
                          border: 'none',
                          borderRadius: '5px',
                          padding: '5px 10px',
                          cursor: 'pointer',
                        }}
                      >
                        Копировать
                      </button>
                    )}
                  </div>
                </div>
              </div>
              {/* Блок управления запросами */}
              <div
                style={{
                  display: 'flex',
                  gap: '20px',
                  marginBottom: '20px',
                  padding: '20px',
                  background: '#fff',
                  borderRadius: '8px',
                  boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
                }}
              >
                <div style={{ flex: 1 }}>
                  <h2>Управление запросами</h2>
                  {/* Блок выбора вида услуг */}
                  <div style={{ marginBottom: '10px' }}>
                    <h2>Вид услуги</h2>
                    <select
                      value={selectedService}
                      onChange={(e) => setSelectedService(e.target.value)}
                      style={{ padding: '5px', borderRadius: '5px' }}
                    >
                      {serviceOptions.map((opt) => (
                        <option key={opt.serviceCode} value={opt.serviceCode}>
                          {opt.description}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <input
                      type="text"
                      placeholder="Введите Order ID запроса"
                      value={orderId}
                      onChange={(e) => setOrderId(e.target.value)}
                      style={{ padding: '5px', marginRight: '10px' }}
                    />
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <button
                      onClick={reserveOrder}
                      style={
                        allowBtn
                          ? {
                              padding: '5px 10px',
                              borderRadius: '5px',
                              border: 'none',
                              background: '#005533',
                              color: '#fff',
                              cursor: 'pointer',
                              marginRight: '10px',
                            }
                          : {
                              padding: '5px 10px',
                              borderRadius: '5px',
                              border: 'none',
                              background: '#000',
                              color: '#fff',
                              cursor: 'not-allowed',
                              marginRight: '10px',
                            }
                      }
                      disabled={!allowBtn}
                    >
                      Зарезервировать новый запрос
                    </button>

                    <button
                      onClick={newOrder}
                      style={
                        allowBtn && zipSize <= 52428800
                          ? {
                              padding: '5px 10px',
                              borderRadius: '5px',
                              border: 'none',
                              background: '#28a745',
                              color: '#fff',
                              cursor: 'pointer',
                              marginRight: '10px',
                            }
                          : {
                              padding: '5px 10px',
                              borderRadius: '5px',
                              border: 'none',
                              background: '#000',
                              color: '#fff',
                              cursor: 'not-allowed',
                              marginRight: '10px',
                            }
                      }
                      disabled={!allowBtn && zipSize <= 52428800}
                    >
                      Создать новый запрос
                    </button>
                    <button
                      onClick={createOrderExtended}
                      style={
                        allowBtn
                          ? {
                              padding: '5px 10px',
                              borderRadius: '5px',
                              border: 'none',
                              background: '#17a2b8',
                              color: '#fff',
                              cursor: 'pointer',
                              marginRight: '10px',
                            }
                          : {
                              padding: '5px 10px',
                              borderRadius: '5px',
                              border: 'none',
                              background: '#000',
                              color: '#fff',
                              cursor: 'not-allowed',
                              marginRight: '10px',
                            }
                      }
                      disabled={!allowBtn}
                    >
                      Создать расширенный запрос
                    </button>
                    <button
                      onClick={cancelOrder}
                      style={{
                        padding: '5px 10px',
                        borderRadius: '5px',
                        border: 'none',
                        background: '#dc3545',
                        color: '#fff',
                        cursor: 'pointer',
                        marginRight: '10px',
                      }}
                    >
                      Отменить запрос
                    </button>
                    <button
                      onClick={() => checkOrderDetailsMain(orderId)}
                      style={{
                        padding: '5px 10px',
                        borderRadius: '5px',
                        border: 'none',
                        background: '#ffc107',
                        color: '#fff',
                        cursor: 'pointer',
                      }}
                    >
                      Проверить статус запроса
                    </button>
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <p>
                      Размер будущего архива:{' '}
                      {(zipSize / (1024 * 1024)).toFixed(2)} MB
                    </p>
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <button
                      onClick={handleFillXml}
                      style={{
                        padding: '5px 10px',
                        borderRadius: '5px',
                        border: 'none',
                        background: '#6f42c1',
                        color: '#fff',
                        cursor: 'pointer',
                      }}
                    >
                      Заполнить XML
                    </button>
                  </div>
                </div>
                <div
                  style={{
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    overflow: 'hidden',
                    padding: '10px',
                  }}
                >
                  <button
                    onClick={() => downloadOrderFile(orderId)}
                    disabled={!isFileAvailable}
                    style={
                      isFileAvailable
                        ? {
                            padding: '5px 10px',
                            borderRadius: '5px',
                            border: 'none',
                            background: '#007bff',
                            color: '#fff',
                            cursor: 'pointer',
                            marginBottom: '10px',
                          }
                        : {
                            padding: '5px 10px',
                            borderRadius: '5px',
                            border: 'none',
                            background: '#a4a4a4',
                            color: '#fff',
                            cursor: 'none',
                            marginBottom: '10px',
                          }
                    }
                  >
                    Скачать файл ответа
                  </button>
                  <div
                    style={{
                      flex: 1,
                      overflowY: 'auto',
                      margin: '10px',
                      background: '#f4f4f4',
                      padding: '10px',
                      borderRadius: '5px',
                    }}
                    onMouseEnter={() => setCopyButtonIndex(4)}
                    onMouseLeave={() => setCopyButtonIndex(null)}
                  >
                    {copyButtonIndex === 4 && (
                      <button
                        onClick={() =>
                          copyToClipboard(
                            JSON.stringify(responseStatusOrder, null, 2)
                          )
                        }
                        style={{
                          position: 'absolute',
                          top: '50%',
                          right: '5%',
                          transform: 'translateY(-50%)',
                          background: 'transparent',
                          color: '#007bff',
                          border: 'none',
                          borderRadius: '5px',
                          padding: '5px 10px',
                          cursor: 'pointer',
                          fontSize: '14px',
                          zIndex: 9999,
                        }}
                      >
                        Копировать
                      </button>
                    )}
                    <pre style={{ margin: 0 }}>
                      {JSON.stringify(responseStatusOrder, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
              {/* Блок File Upload */}
              <div
                style={{
                  marginBottom: '20px',
                  padding: '20px',
                  background: '#fff',
                  borderRadius: '8px',
                  boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
                }}
              >
                <h2>File Upload</h2>
                <FileDropzone
                  onDrop={handleFileDrop}
                  files={files}
                  setFiles={setFiles}
                  description="Перетащите файлы сюда или нажмите для выбора"
                />
              </div>
            </div>
          )}
          {/* Таб для XML редактора */}
          {currentTab === 'xml' && (
            <div
              style={{
                display: 'flex',
                height: '600px',
                marginBottom: '20px',
                background: '#fff',
                borderRadius: '8px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
              }}
            >
              <div
                style={{
                  width: '250px',
                  padding: '10px',
                  borderRight: '1px solid #ccc',
                  overflowY: 'auto',
                }}
              >
                <h3>Список XML</h3>
                <ul style={{ listStyle: 'none', padding: 0 }}>
                  {xmlDocuments.map((doc, idx) => (
                    <li
                      key={idx}
                      style={{
                        padding: '10px',
                        cursor: 'pointer',
                        backgroundColor:
                          selectedXmlIndex === idx ? '#007bff' : 'transparent',
                        color: selectedXmlIndex === idx ? '#fff' : '#000',
                        borderRadius: '5px',
                        marginBottom: '5px',
                      }}
                      onClick={() => setSelectedXmlIndex(idx)}
                    >
                      {doc.name}
                    </li>
                  ))}
                </ul>
                <button
                  onClick={() => {
                    const newDoc = {
                      name: `Document${xmlDocuments.length + 1}`,
                      content: '<root>\n  <!-- Новый XML -->\n</root>',
                    };
                    setXmlDocuments([...xmlDocuments, newDoc]);
                    setSelectedXmlIndex(xmlDocuments.length);
                  }}
                  style={{
                    padding: '10px',
                    borderRadius: '5px',
                    border: 'none',
                    background: '#007bff',
                    color: '#fff',
                    cursor: 'pointer',
                    width: '100%',
                  }}
                >
                  Добавить новый XML
                </button>
              </div>
              <div style={{ flexGrow: 1, padding: '10px' }}>
                <h2>{xmlDocuments[selectedXmlIndex]?.name}</h2>
                <AceEditor
                  mode="xml"
                  theme="github"
                  onChange={updateXmlContent}
                  value={xmlDocuments[selectedXmlIndex]?.content || ''}
                  name="xml_editor"
                  editorProps={{ $blockScrolling: true }}
                  width="100%"
                  height="500px"
                  setOptions={{
                    useWorker: true,
                    highlightActiveLine: true,
                    showLineNumbers: true,
                    tabSize: 2,
                  }}
                />
                <div
                  style={{ marginTop: '40px', display: 'flex', gap: '10px' }}
                >
                  <button
                    onClick={prettifyXml}
                    style={{
                      padding: '10px',
                      borderRadius: '5px',
                      border: 'none',
                      background: '#28a745',
                      color: '#fff',
                      cursor: 'pointer',
                    }}
                  >
                    Форматировать XML
                  </button>
                  <button
                    onClick={saveXmlFile}
                    style={{
                      padding: '10px',
                      borderRadius: '5px',
                      border: 'none',
                      background: '#007bff',
                      color: '#fff',
                      cursor: 'pointer',
                    }}
                  >
                    Сохранить XML
                  </button>
                  <label
                    htmlFor="uploadXml"
                    style={{
                      padding: '5px 10px',
                      borderRadius: '5px',
                      border: 'none',
                      background: '#17a2b8',
                      color: '#fff',
                      cursor: 'pointer',
                      marginRight: '10px',
                    }}
                  >
                    Загрузить XML
                  </label>
                  <input
                    id="uploadXml"
                    type="file"
                    accept=".xml"
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      if (e.target.files && e.target.files.length > 0)
                        loadXmlFromFile(e.target.files[0]);
                    }}
                  />
                  <button
                    onClick={() => handleFillXml()}
                    style={{
                      padding: '5px 10px',
                      borderRadius: '5px',
                      border: 'none',
                      background: '#6f42c1',
                      color: '#fff',
                      cursor: 'pointer',
                    }}
                  >
                    Заполнить XML
                  </button>
                  <button
                    onClick={() => updateXmlDocuments(selectedService, true)}
                    style={{
                      padding: '5px 10px',
                      borderRadius: '5px',
                      border: 'none',
                      background: '#dc3545',
                      color: '#fff',
                      cursor: 'pointer',
                    }}
                  >
                    Очистить XML
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Табы для запросов */}
          {currentTab === 'requests' && (
            <div
              style={{
                background: '#fff',
                padding: '20px',
                borderRadius: '8px',
                boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
              }}
            >
              <h2>Запросы</h2>
              <button
                onClick={fetchUpdatedOrders}
                style={{
                  marginBottom: '10px',
                  padding: '5px 10px',
                  borderRadius: '5px',
                  border: 'none',
                  background: '#17a2b8',
                  color: '#fff',
                  cursor: 'pointer',
                }}
              >
                Получить все запросы
              </button>
              <div style={{ marginBottom: '10px' }}>
                <label style={{ marginRight: '10px' }}>Дата обновления:</label>
                <DatePicker
                  selected={updatedAfter}
                  onChange={(date) => {
                    setUpdatedAfter(date);
                  }}
                  showTimeSelect
                  dateFormat="yyyy-MM-dd HH:mm"
                />
              </div>
              <div style={{ marginBottom: '10px' }}>
                <label style={{ marginRight: '10px' }}>
                  Элементов в запросе:
                </label>
                <select
                  value={totalRecords}
                  onChange={(e) => {
                    setTotalRecords(Number(e.target.value));
                    setPageNum(0);
                    fetchUpdatedOrders();
                  }}
                  style={{ padding: '5px', borderRadius: '5px' }}
                >
                  <option value={10}>10</option>
                  <option value={20}>50</option>
                  <option value={50}>100</option>
                </select>
              </div>
              <div style={{ marginBottom: '10px' }}>
                <label>Элементов на странице:</label>
                <select
                  value={pageSize}
                  onChange={(e) => setPageSize(Number(e.target.value))}
                  style={{ padding: '5px', borderRadius: '5px' }}
                >
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                </select>
              </div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  marginBottom: '10px',
                }}
              >
                <button
                  onClick={() => setPageNum((prev) => Math.max(prev - 1, 0))}
                  disabled={pageNum === 0}
                  style={{
                    padding: '5px 10px',
                    cursor: pageNum === 0 ? 'not-allowed' : 'pointer',
                  }}
                >
                  Назад
                </button>
                <span>
                  Страница: {pageNum + 1} из{' '}
                  {Math.ceil((responseTable?.content?.length || 0) / pageSize)}
                </span>
                <button
                  onClick={() =>
                    setPageNum((prev) =>
                      (prev + 1) * pageSize <
                      (responseTable?.content?.length || 0)
                        ? prev + 1
                        : prev
                    )
                  }
                  disabled={
                    (pageNum + 1) * pageSize >=
                    (responseTable?.content?.length || 0)
                  }
                  style={{
                    padding: '5px 10px',
                    cursor:
                      (pageNum + 1) * pageSize >=
                      (responseTable?.content?.length || 0)
                        ? 'not-allowed'
                        : 'pointer',
                  }}
                >
                  Вперёд
                </button>
              </div>
              <div
                style={{
                  display: 'flex',
                  gap: '20px',
                  height: 'calc(100vh - 200px)',
                }}
              >
                <div
                  style={{
                    width: `${leftWidth}%`,
                    borderRight: '1px solid #ccc',
                    overflow: 'auto',
                  }}
                >
                  <table
                    style={{
                      width: '100%',
                      borderCollapse: 'collapse',
                      height: '100%',
                    }}
                  >
                    <thead>
                      <tr>
                        <th
                          style={{ border: '1px solid #ccc', padding: '10px' }}
                        >
                          Order ID
                        </th>
                        <th
                          style={{ border: '1px solid #ccc', padding: '10px' }}
                        >
                          Статус
                        </th>
                        <th
                          style={{ border: '1px solid #ccc', padding: '10px' }}
                        >
                          Обновлено
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {responseTable?.length > 0 ? (
                        responseTable.map((item, idx) => (
                          <tr
                            key={idx}
                            style={
                              item?.orderId === selectItem
                                ? { background: '#a4a4a4' }
                                : {}
                            }
                          >
                            <td
                              style={{
                                border: '1px solid #ccc',
                                padding: '10px',
                              }}
                            >
                              <div
                                style={{
                                  position: 'relative',
                                  margin: '10px',
                                  background: '#f4f4f4',
                                  padding: '10px',
                                  borderRadius: '5px',
                                  overflowX: 'auto',
                                }}
                                onClick={() =>
                                  checkOrderDetailsItem(item.orderId)
                                }
                                onMouseEnter={() => setCopyButtonIndex(3)}
                                onMouseLeave={() => setCopyButtonIndex(null)}
                              >
                                {item.orderId}
                                {copyButtonIndex === 3 && (
                                  <button
                                    onClick={() =>
                                      copyToClipboard(item.orderId)
                                    }
                                    style={{
                                      position: 'absolute',
                                      top: '50%',
                                      right: '10px',
                                      transform: 'translateY(-50%)',
                                      background: 'transparent',
                                      color: '#007bff',
                                      border: 'none',
                                      borderRadius: '5px',
                                      padding: '5px 10px',
                                      cursor: 'pointer',
                                      fontSize: '14px',
                                    }}
                                  >
                                    Копировать
                                  </button>
                                )}
                              </div>
                            </td>
                            <td
                              style={{
                                border: '1px solid #ccc',
                                padding: '10px',
                              }}
                            >
                              <div
                                style={{
                                  position: 'relative',
                                  margin: '10px',
                                  background: '#f4f4f4',
                                  padding: '10px',
                                  borderRadius: '5px',
                                  overflowX: 'auto',
                                }}
                                onClick={() =>
                                  checkOrderDetailsItem(item.orderId)
                                }
                              >
                                {item.status.statusName}
                              </div>
                            </td>
                            <td
                              style={{
                                border: '1px solid #ccc',
                                padding: '10px',
                              }}
                            >
                              <div
                                style={{
                                  position: 'relative',
                                  margin: '10px',
                                  background: '#f4f4f4',
                                  padding: '10px',
                                  borderRadius: '5px',
                                  overflowX: 'auto',
                                }}
                                onClick={() =>
                                  checkOrderDetailsItem(item.orderId)
                                }
                              >
                                {item.status.updated}
                              </div>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td
                            colSpan={3}
                            style={{ textAlign: 'center', padding: '10px' }}
                          >
                            Нет данных для отображения
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
                <div
                  style={{
                    width: '5px',
                    cursor: 'col-resize',
                    backgroundColor: '#aaa',
                  }}
                  onMouseDown={handleMouseDown}
                ></div>
                <div
                  style={{
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    overflow: 'hidden',
                    padding: '10px',
                  }}
                >
                  <button
                    onClick={() =>
                      downloadOrderFile(responseStatusItem.order?.id)
                    }
                    disabled={!isFileItemAvailable}
                    style={
                      isFileItemAvailable
                        ? {
                            padding: '5px 10px',
                            borderRadius: '5px',
                            border: 'none',
                            background: '#007bff',
                            color: '#fff',
                            cursor: 'pointer',
                            marginBottom: '10px',
                          }
                        : {
                            padding: '5px 10px',
                            borderRadius: '5px',
                            border: 'none',
                            background: '#a4a4a4',
                            color: '#fff',
                            cursor: 'none',
                            marginBottom: '10px',
                          }
                    }
                  >
                    Скачать файл ответа
                  </button>
                  <div
                    style={{
                      flex: 1,
                      overflowY: 'auto',
                      margin: '10px',
                      background: '#f4f4f4',
                      padding: '10px',
                      borderRadius: '5px',
                    }}
                    onMouseEnter={() => setCopyButtonIndex(4)}
                    onMouseLeave={() => setCopyButtonIndex(null)}
                  >
                    {copyButtonIndex === 4 && (
                      <button
                        onClick={() =>
                          copyToClipboard(
                            JSON.stringify(responseStatusItem, null, 2)
                          )
                        }
                        style={{
                          position: 'absolute',
                          top: '50%',
                          right: '5%',
                          transform: 'translateY(-50%)',
                          background: 'transparent',
                          color: '#007bff',
                          border: 'none',
                          borderRadius: '5px',
                          padding: '5px 10px',
                          cursor: 'pointer',
                          fontSize: '14px',
                          zIndex: 9999,
                        }}
                      >
                        Копировать
                      </button>
                    )}
                    <pre style={{ margin: 0 }}>
                      {JSON.stringify(responseStatusItem, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

export default App;
