import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Layout,
  Menu,
  Button,
  Card,
  Select,
  Input,
  Space,
  Typography,
  Row,
  Col,
  Table,
  DatePicker as AntDatePicker,
  ConfigProvider,
  theme,
  Divider,
  Tag,
} from 'antd';
import {
  HomeOutlined,
  CodeOutlined,
  UnorderedListOutlined,
  SafetyCertificateOutlined,
  KeyOutlined,
  DeleteOutlined,
  PlusOutlined,
  SendOutlined,
  CloseCircleOutlined,
  SearchOutlined,
  DownloadOutlined,
  FormatPainterOutlined,
  SaveOutlined,
  UploadOutlined,
  ClearOutlined,
  ReloadOutlined,
  FileTextOutlined,
  CopyOutlined,
  CheckCircleOutlined,
  ApiOutlined,
} from '@ant-design/icons';
import axios from 'axios';
import moment from 'moment-timezone';
import dayjs from 'dayjs';
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

const { Header, Content } = Layout;
const { Title, Text, Paragraph } = Typography;
const { Option } = Select;

const BACKEND_URL =
  process.env.REACT_APP_BACKEND_URL || '/api';

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
        const services = Array.isArray(response.data) ? response.data : [];
        setServiceOptions(services);
        if (services.length > 0) {
          setSelectedService(services[0].serviceCode);
        }
      })
      .catch((error) => {
        console.error('Ошибка получения услуг', error);
        setServiceOptions([]);
      });
    const fetchCertificates = async () => {
      try {
        const res = await api.post('/get_certificates');
        const certs = Array.isArray(res.data) ? res.data : [];
        if (certs.length > 0) {
          setCertificates(certs);
          setSelectedCertId(certs[0].id);
        } else {
          setStatus('Нет доступных сертификатов.');
          setCertificates([]);
        }
      } catch (e) {
        console.error('Ошибка загрузки сертификатов:', e);
        setStatus('Ошибка загрузки сертификатов.');
        setCertificates([]);
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

  const requestsColumns = [
    {
      title: 'Order ID',
      dataIndex: 'orderId',
      key: 'orderId',
      render: (text, record) => (
        <Paragraph
          copyable={{ icon: [<CopyOutlined key="copy" />, <CheckCircleOutlined key="copied" />] }}
          style={{ margin: 0, cursor: 'pointer' }}
          onClick={() => checkOrderDetailsItem(record.orderId)}
        >
          {text}
        </Paragraph>
      ),
    },
    {
      title: 'Статус',
      dataIndex: ['status', 'statusName'],
      key: 'status',
      render: (text, record) => (
        <Tag
          color="processing"
          style={{ cursor: 'pointer' }}
          onClick={() => checkOrderDetailsItem(record.orderId)}
        >
          {text}
        </Tag>
      ),
    },
    {
      title: 'Обновлено',
      dataIndex: ['status', 'updated'],
      key: 'updated',
      render: (text, record) => (
        <Text
          style={{ cursor: 'pointer' }}
          onClick={() => checkOrderDetailsItem(record.orderId)}
        >
          {text}
        </Text>
      ),
    },
  ];

  return (
    <ConfigProvider
      theme={{
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: '#1677ff',
          borderRadius: 8,
          fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        },
      }}
    >
      <Layout style={{ minHeight: '100vh', background: '#f5f7fa' }}>
        <Header
          style={{
            background: '#fff',
            padding: '0 32px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            boxShadow: '0 1px 4px rgba(0,0,0,0.08)',
            position: 'sticky',
            top: 0,
            zIndex: 100,
            height: 64,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <img src={logo} alt="Логотип" style={{ height: 36 }} />
            <Title level={4} style={{ margin: 0, fontWeight: 600 }}>
              API Client
            </Title>
          </div>
          <Menu
            mode="horizontal"
            selectedKeys={[currentTab]}
            onClick={({ key }) => setCurrentTab(key)}
            style={{ border: 'none', fontWeight: 500 }}
            items={[
              { key: 'main', icon: <HomeOutlined />, label: 'Главная' },
              { key: 'xml', icon: <CodeOutlined />, label: 'Редактор XML' },
              { key: 'requests', icon: <UnorderedListOutlined />, label: 'Запросы' },
            ]}
          />
        </Header>

        <Content style={{ padding: '24px 32px', maxWidth: 1400, margin: '0 auto', width: '100%' }}>
          {/* Блок статуса */}
          <Card
            size="small"
            style={{ marginBottom: 24 }}
            styles={{ body: { padding: '16px 24px' } }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: status || responseData ? 12 : 0 }}>
              <Title level={5} style={{ margin: 0 }}>Статус</Title>
              <Button icon={<ApiOutlined />} onClick={checkAPI}>
                Проверить API Client
              </Button>
              {status && <Text type="secondary">{status}</Text>}
            </div>
            {responseData && (
              <Paragraph
                copyable
                style={{
                  background: '#f8f9fa',
                  padding: 12,
                  borderRadius: 6,
                  margin: 0,
                  fontFamily: 'monospace',
                  fontSize: 13,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {typeof responseData === 'string' ? responseData : JSON.stringify(responseData, null, 2)}
              </Paragraph>
            )}
          </Card>

          {/* Основная вкладка */}
          {currentTab === 'main' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              {/* Блок сертификатов и токена */}
              <Card title={<><SafetyCertificateOutlined style={{ marginRight: 8 }} />Сертификаты и токен</>}>
                <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                  <div>
                    <Text strong style={{ marginRight: 12 }}>Выберите сертификат:</Text>
                    <Select
                      value={selectedCertId}
                      onChange={(value) => setCurrentCertificate(value)}
                      style={{ minWidth: 400 }}
                      placeholder="Выберите сертификат"
                    >
                      {Array.isArray(certificates) && certificates.length > 0 ? (
                        certificates.map((cert) => (
                          <Option key={cert.id} value={cert.id}>
                            {cert.subject} (Valid: {cert.valid_from} - {cert.valid_to})
                          </Option>
                        ))
                      ) : (
                        <Option value="" disabled>Сертификаты не найдены</Option>
                      )}
                    </Select>
                  </div>
                  <Space>
                    <Input
                      placeholder="Введите API key"
                      prefix={<KeyOutlined />}
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      style={{ width: 280 }}
                    />
                    <Button
                      type="primary"
                      icon={<CheckCircleOutlined />}
                      onClick={fetchAccessToken}
                    >
                      Получить токен
                    </Button>
                    <Button
                      danger
                      icon={<DeleteOutlined />}
                      onClick={handleLogout}
                    >
                      Удалить токен
                    </Button>
                  </Space>
                  {token && (
                    <Paragraph
                      copyable
                      style={{
                        background: '#f8f9fa',
                        padding: 12,
                        borderRadius: 6,
                        margin: 0,
                        fontFamily: 'monospace',
                        fontSize: 12,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        maxHeight: 120,
                        overflow: 'auto',
                      }}
                    >
                      {token}
                    </Paragraph>
                  )}
                </Space>
              </Card>

              {/* Блок управления запросами */}
              <Card title={<><SendOutlined style={{ marginRight: 8 }} />Управление запросами</>}>
                <Row gutter={24}>
                  <Col xs={24} lg={12}>
                    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                      <div>
                        <Text strong style={{ display: 'block', marginBottom: 8 }}>Вид услуги</Text>
                        <Select
                          value={selectedService}
                          onChange={(value) => setSelectedService(value)}
                          style={{ width: '100%' }}
                          placeholder="Выберите услугу"
                        >
                          {Array.isArray(serviceOptions) && serviceOptions.length > 0 ? (
                            serviceOptions.map((opt) => (
                              <Option key={opt.serviceCode} value={opt.serviceCode}>
                                {opt.description}
                              </Option>
                            ))
                          ) : (
                            <Option value="" disabled>Загрузка услуг...</Option>
                          )}
                        </Select>
                      </div>
                      <Input
                        placeholder="Введите Order ID запроса"
                        value={orderId}
                        onChange={(e) => setOrderId(e.target.value)}
                        style={{ width: '100%' }}
                      />
                      <Space wrap>
                        <Button
                          type="primary"
                          icon={<PlusOutlined />}
                          onClick={reserveOrder}
                          disabled={!allowBtn}
                        >
                          Зарезервировать
                        </Button>
                        <Button
                          type="primary"
                          icon={<SendOutlined />}
                          onClick={newOrder}
                          disabled={!allowBtn || zipSize > 52428800}
                          style={{ background: allowBtn && zipSize <= 52428800 ? '#52c41a' : undefined }}
                        >
                          Создать запрос
                        </Button>
                        <Button
                          icon={<PlusOutlined />}
                          onClick={createOrderExtended}
                          disabled={!allowBtn}
                        >
                          Расширенный запрос
                        </Button>
                        <Button
                          danger
                          icon={<CloseCircleOutlined />}
                          onClick={cancelOrder}
                        >
                          Отменить
                        </Button>
                        <Button
                          icon={<SearchOutlined />}
                          onClick={() => checkOrderDetailsMain(orderId)}
                        >
                          Проверить статус
                        </Button>
                      </Space>
                      <Text type="secondary">
                        Размер будущего архива: {(zipSize / (1024 * 1024)).toFixed(2)} MB
                      </Text>
                      <Button
                        icon={<FileTextOutlined />}
                        onClick={handleFillXml}
                      >
                        Заполнить XML
                      </Button>
                    </Space>
                  </Col>
                  <Col xs={24} lg={12}>
                    <Space direction="vertical" size="middle" style={{ width: '100%', height: '100%' }}>
                      <Button
                        type="primary"
                        icon={<DownloadOutlined />}
                        onClick={() => downloadOrderFile(orderId)}
                        disabled={!isFileAvailable}
                        block
                      >
                        Скачать файл ответа
                      </Button>
                      <div
                        style={{
                          flex: 1,
                          background: '#f8f9fa',
                          padding: 12,
                          borderRadius: 6,
                          minHeight: 200,
                          maxHeight: 400,
                          overflow: 'auto',
                        }}
                      >
                        <Paragraph
                          copyable={!!responseStatusOrder}
                          style={{
                            margin: 0,
                            fontFamily: 'monospace',
                            fontSize: 13,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                          }}
                        >
                          {JSON.stringify(responseStatusOrder, null, 2)}
                        </Paragraph>
                      </div>
                    </Space>
                  </Col>
                </Row>
              </Card>

              {/* Блок File Upload */}
              <Card title={<><UploadOutlined style={{ marginRight: 8 }} />Загрузка файлов</>}>
                <FileDropzone
                  onDrop={handleFileDrop}
                  files={files}
                  setFiles={setFiles}
                  description="Перетащите файлы сюда или нажмите для выбора"
                />
              </Card>
            </div>
          )}

          {/* Таб для XML редактора */}
          {currentTab === 'xml' && (
            <Card styles={{ body: { padding: 0 } }} style={{ overflow: 'hidden' }}>
              <div style={{ display: 'flex', height: 650 }}>
                <div
                  style={{
                    width: 250,
                    borderRight: '1px solid #f0f0f0',
                    padding: 16,
                    overflowY: 'auto',
                    background: '#fafafa',
                  }}
                >
                  <Title level={5} style={{ marginTop: 0 }}>Список XML</Title>
                  <Menu
                    mode="inline"
                    selectedKeys={[String(selectedXmlIndex)]}
                    onClick={({ key }) => setSelectedXmlIndex(Number(key))}
                    style={{ border: 'none', background: 'transparent' }}
                    items={xmlDocuments.map((doc, idx) => ({
                      key: String(idx),
                      icon: <FileTextOutlined />,
                      label: doc.name,
                    }))}
                  />
                  <Divider style={{ margin: '12px 0' }} />
                  <Button
                    type="dashed"
                    icon={<PlusOutlined />}
                    block
                    onClick={() => {
                      const newDoc = {
                        name: `Document${xmlDocuments.length + 1}`,
                        content: '<root>\n  <!-- Новый XML -->\n</root>',
                      };
                      setXmlDocuments([...xmlDocuments, newDoc]);
                      setSelectedXmlIndex(xmlDocuments.length);
                    }}
                  >
                    Добавить XML
                  </Button>
                </div>
                <div style={{ flex: 1, padding: 16, display: 'flex', flexDirection: 'column' }}>
                  <Title level={4} style={{ marginTop: 0 }}>
                    {xmlDocuments[selectedXmlIndex]?.name}
                  </Title>
                  <div style={{ flex: 1 }}>
                    <AceEditor
                      mode="xml"
                      theme="github"
                      onChange={updateXmlContent}
                      value={xmlDocuments[selectedXmlIndex]?.content || ''}
                      name="xml_editor"
                      editorProps={{ $blockScrolling: true }}
                      width="100%"
                      height="480px"
                      setOptions={{
                        useWorker: true,
                        highlightActiveLine: true,
                        showLineNumbers: true,
                        tabSize: 2,
                      }}
                    />
                  </div>
                  <Divider style={{ margin: '12px 0' }} />
                  <Space wrap>
                    <Button
                      type="primary"
                      icon={<FormatPainterOutlined />}
                      onClick={prettifyXml}
                      style={{ background: '#52c41a' }}
                    >
                      Форматировать
                    </Button>
                    <Button
                      type="primary"
                      icon={<SaveOutlined />}
                      onClick={saveXmlFile}
                    >
                      Сохранить
                    </Button>
                    <Button icon={<UploadOutlined />} onClick={() => document.getElementById('uploadXml').click()}>
                      Загрузить
                    </Button>
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
                    <Button icon={<FileTextOutlined />} onClick={() => handleFillXml()}>
                      Заполнить XML
                    </Button>
                    <Button
                      danger
                      icon={<ClearOutlined />}
                      onClick={() => updateXmlDocuments(selectedService, true)}
                    >
                      Очистить
                    </Button>
                  </Space>
                </div>
              </div>
            </Card>
          )}

          {/* Табы для запросов */}
          {currentTab === 'requests' && (
            <Card>
              <Title level={4} style={{ marginTop: 0 }}>Запросы</Title>
              <Space direction="vertical" size="middle" style={{ width: '100%', marginBottom: 16 }}>
                <Space wrap>
                  <Button
                    type="primary"
                    icon={<ReloadOutlined />}
                    onClick={fetchUpdatedOrders}
                  >
                    Получить все запросы
                  </Button>
                  <Space>
                    <Text>Дата обновления:</Text>
                    <AntDatePicker
                      showTime
                      format="YYYY-MM-DD HH:mm"
                      value={updatedAfter ? dayjs(updatedAfter) : null}
                      onChange={(date) => {
                        setUpdatedAfter(date ? date.toDate() : new Date());
                      }}
                    />
                  </Space>
                  <Space>
                    <Text>Элементов в запросе:</Text>
                    <Select
                      value={totalRecords}
                      onChange={(value) => {
                        setTotalRecords(value);
                        setPageNum(0);
                        fetchUpdatedOrders();
                      }}
                      style={{ width: 80 }}
                    >
                      <Option value={10}>10</Option>
                      <Option value={20}>50</Option>
                      <Option value={50}>100</Option>
                    </Select>
                  </Space>
                </Space>
              </Space>

              <Row gutter={16} style={{ height: 'calc(100vh - 320px)' }}>
                <Col flex={`${leftWidth}%`} style={{ overflow: 'auto' }}>
                  <Table
                    columns={requestsColumns}
                    dataSource={responseTable || []}
                    rowKey={(record, idx) => record.orderId || idx}
                    pagination={{
                      pageSize,
                      showSizeChanger: true,
                      pageSizeOptions: ['10', '20', '50'],
                      onShowSizeChange: (_, size) => setPageSize(size),
                    }}
                    size="small"
                    onRow={(record) => ({
                      style:
                        record?.orderId === selectItem
                          ? { background: '#e6f4ff' }
                          : {},
                      onClick: () => checkOrderDetailsItem(record.orderId),
                    })}
                    scroll={{ y: 'calc(100vh - 440px)' }}
                  />
                </Col>
                <Col
                  style={{
                    width: 6,
                    cursor: 'col-resize',
                    background: '#f0f0f0',
                    borderRadius: 3,
                    flexShrink: 0,
                  }}
                  onMouseDown={handleMouseDown}
                />
                <Col flex="auto" style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                  <Button
                    type="primary"
                    icon={<DownloadOutlined />}
                    onClick={() => downloadOrderFile(responseStatusItem?.order?.id)}
                    disabled={!isFileItemAvailable}
                    block
                    style={{ marginBottom: 12 }}
                  >
                    Скачать файл ответа
                  </Button>
                  <div
                    style={{
                      flex: 1,
                      background: '#f8f9fa',
                      padding: 12,
                      borderRadius: 6,
                      overflow: 'auto',
                    }}
                  >
                    <Paragraph
                      copyable={!!responseStatusItem}
                      style={{
                        margin: 0,
                        fontFamily: 'monospace',
                        fontSize: 13,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {JSON.stringify(responseStatusItem, null, 2)}
                    </Paragraph>
                  </div>
                </Col>
              </Row>
            </Card>
          )}
        </Content>
      </Layout>
    </ConfigProvider>
  );
}

export default App;
