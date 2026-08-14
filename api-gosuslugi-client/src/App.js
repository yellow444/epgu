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
  FloatButton,
} from 'antd';
import {
  HomeOutlined,
  SettingOutlined,
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
  VerticalAlignTopOutlined,
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
import GoskeyForm, {
  GOSKEY_ROUTES,
  createGoskeySubmissionFormData,
  isGoskeyServiceProfile,
} from './components/GoskeyForm/GoskeyForm';
import SetupGuide from './components/SetupGuide/SetupGuide';
import {
  applyServiceTransforms,
  buildXmlFilesForService,
  createLatestRequestGate,
  createTemplateContext,
  getDefaultSubmissionMode,
  getSubmissionModes,
  normalizeServices,
  renderDocumentName,
  renderTemplateName,
  selectInitialService,
  toScalarSubmissionContext,
} from './serviceProfiles';
import logo from './logo.gosuslugi.svg';
import {
  downloadFilesSequentially,
  saveBlobResponse,
} from './downloads';
import { logError } from './safeLogging';
import {
  certificateDetails,
  certificateOptionLabel,
} from './certificateDisplay';
import { exactOrderId, isValidOrderId, orderRoute } from './orderId';

const { Header, Content } = Layout;
const { Title, Text, Paragraph } = Typography;
const { Option } = Select;

const BACKEND_URL =
  process.env.REACT_APP_BACKEND_URL || '/api';

const LEGACY_SENSITIVE_KEYS = [
  'filesList',
  'paginatedData',
  'responseData',
  'responseStatusItem',
  'responseStatusOrder',
  'responseTable',
  'selectItem',
  'updatedAfter',
  'xmlDocuments',
];

const purgeLegacyPersistentData = () => {
  LEGACY_SENSITIVE_KEYS.forEach((key) => localStorage.removeItem(key));
  if (window.indexedDB) {
    // Previous releases cached complete uploaded files in ``files-db``.
    // New releases are memory-only and remove that legacy cache on startup.
    window.indexedDB.deleteDatabase('files-db');
  }
};

function App() {
  // Основные рефы и состояния
  const isDragging = useRef(false);
  const [allowBtn, setAllowBtn] = useState(true);
  const [leftWidth, setLeftWidth] = useState(50);
  const [currentTab, setCurrentTab] = useState(
    sessionStorage.getItem('currentTab') || 'main'
  );

  const [selectItem, setSelectItem] = useState([]);
  // Сертификаты, токен, API key и OrderID
  const cancelTokenSourceRef = useRef(null);
  const requestIdRef = useRef(0);
  const selectedServiceRef = useRef('');
  const xmlRequestGateRef = useRef(null);
  if (!xmlRequestGateRef.current) {
    xmlRequestGateRef.current = createLatestRequestGate();
  }
  const [token, setToken] = useState(sessionStorage.getItem('token') || '');
  const [tokenVisible, setTokenVisible] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [certificates, setCertificates] = useState([]);
  const [selectedCertId, setSelectedCertId] = useState('');
  const [orderId, setOrderId] = useState(
    sessionStorage.getItem('orderId') || ''
  );
  const [status, setStatus] = useState('');

  // Файлы для загрузки и размер будущего ZIP
  const [files, setFiles] = useState([]);
  const [zipSize, setZipSize] = useState(0); // в байтах

  // XML документы (по умолчанию два: req и piev_epgu)
  const [xmlDocuments, setXmlDocuments] = useState([]);

  const [selectedXmlIndex, setSelectedXmlIndex] = useState(0);

  // Выбор вида услуги (от которого меняются XML шаблоны)
  const [selectedService, setSelectedService] = useState('');
  const [runtimeRegion, setRuntimeRegion] = useState('');
  const [serviceOptions, setServiceOptions] = useState([]);
  const [serviceSubmissionContexts, setServiceSubmissionContexts] = useState({});
  const [selectedSubmissionMode, setSelectedSubmissionMode] = useState('push');
  const [goskeyCapabilities, setGoskeyCapabilities] = useState([]);
  const [goskeyPreviewing, setGoskeyPreviewing] = useState(false);
  const [goskeySubmitting, setGoskeySubmitting] = useState(false);
  // Пагинация и дата обновления запросов
  const [updatedAfter, setUpdatedAfter] = useState(() => new Date());

  const [pageNum, setPageNum] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [totalRecords, setTotalRecords] = useState(50);
  const [responseData, setResponseData] = useState();
  const [responseTable, setResponseTable] = useState();
  const [responseStatusOrder, setResponseStatusOrder] = useState();
  const [responseStatusItem, setResponseStatusItem] = useState();
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
    setTokenVisible(false);
  };
  const fetchAccessToken = async () => {
    if (!selectedCertId) {
      setStatus('Сначала явно выберите сертификат.');
      return;
    }
    try {
      const res = await api.post('/accessTkn_esia', { api_key: apiKey });
      const newToken = res.data.accessTkn || '';
      updateToken(newToken);
      setStatus('Токен успешно получен.');
    } catch (e) {
      setStatus('Ошибка получения токена.');
    }
  };
  const handleLogout = async () => {
    let serverCleared = true;
    try {
      await api.post('/session/clear');
    } catch (error) {
      serverCleared = false;
      logError('Не удалось очистить server-side сессию', error);
    }
    sessionStorage.removeItem('token');
    setToken('');
    setTokenVisible(false);
    setApiKey('');
    setSelectedCertId('');
    setStatus(
      serverCleared
        ? 'Сессия, API-Key и выбор сертификата очищены.'
        : 'Локальные данные очищены, но server-side токен/сертификат могли сохраниться. Повторите выход.'
    );
  };

  // XML функции

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

  const clearSensitiveLocalData = async () => {
    let serverCleared = true;
    try {
      await api.post('/session/clear');
    } catch (error) {
      serverCleared = false;
      logError('Не удалось очистить server-side сессию', error);
    }
    localStorage.clear();
    sessionStorage.clear();
    purgeLegacyPersistentData();
    setFiles([]);
    setXmlDocuments([]);
    setOrderId('');
    setToken('');
    setTokenVisible(false);
    setApiKey('');
    setSelectedCertId('');
    setSelectItem([]);
    setResponseData(undefined);
    setResponseTable(undefined);
    setResponseStatusOrder(undefined);
    setResponseStatusItem(undefined);
    setStatus(
      serverCleared
        ? 'Локальные документы, XML, ответы и данные сессии удалены.'
        : 'Локальные данные удалены, но server-side токен/сертификат могли сохраниться. Повторите очистку.'
    );
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
        logError('Ошибка расчёта размера архива', e);
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
    logError('Ошибка запроса к API', e);
  };

  const getActiveService = useCallback(() => {
    return serviceOptions.find((option) => option.serviceCode === selectedService) || {};
  }, [serviceOptions, selectedService]);

  const getOrderMetadataPayload = (overrides = {}) => {
    const service = getActiveService();
    return {
      region: runtimeRegion.trim(),
      serviceCode: service?.eServiceCode || service?.serviceCode,
      targetCode: service?.serviceTargetCode,
      ...overrides,
    };
  };

  const getSubmissionMode = () => selectedSubmissionMode || 'push';

  const getSubmissionContext = () => {
    return toScalarSubmissionContext(serviceSubmissionContexts[selectedService]);
  };

  const getTemplateContext = () =>
    createTemplateContext({
      service: getActiveService(),
      submissionContext: getSubmissionContext(),
      orderId: isValidOrderId(orderId) ? exactOrderId(orderId) : '',
    });

  const isServiceAvailable = () => Boolean(getActiveService().available);
  const serviceUnavailableReason = () =>
    getActiveService().unavailableReason || 'Выберите доступную услугу.';

  const hasValidRuntimeRegion = () => /^\d{2,11}$/.test(runtimeRegion.trim());

  const appendXmlDocuments = (formData) => {
    const service = getActiveService();
    const context = getTemplateContext();
    const preparedDocuments = applyServiceTransforms(
      xmlDocuments,
      service,
      context
    );
    preparedDocuments.forEach((doc) => {
      const blob = new Blob([doc.content], { type: 'application/xml' });
      formData.append(
        'files_upload',
        blob,
        renderDocumentName(doc, service, context) || 'document.xml'
      );
    });
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
  const updateXmlDocumentsWithFiles = () => {
    const service = getActiveService();
    if (!service.available) {
      setStatus(serviceUnavailableReason());
      return;
    }
    try {
      const updatedDocs = applyServiceTransforms(
        xmlDocuments,
        service,
        getTemplateContext()
      );
      setXmlDocuments(updatedDocs);
      setStatus(
        service.transforms.length > 0 || service.serviceCode === '60010153'
          ? 'XML документы заполнены по профилю выбранной услуги.'
          : 'Для услуги не объявлены автоматические XML-преобразования.'
      );
    } catch (error) {
      logError('Ошибка заполнения XML', error);
      setStatus(error.message || 'Ошибка заполнения XML.');
    }
  };

  // При нажатии на кнопку "Заполнить XML"
  const handleFillXml = () => {
    updateXmlDocumentsWithFiles();
  };

  const reserveOrder = async () => {
    if (!isServiceAvailable()) {
      setStatus(serviceUnavailableReason());
      return;
    }
    if (!hasValidRuntimeRegion()) {
      setStatus('Укажите ОКАТО пользователя: от 2 до 11 цифр.');
      return;
    }
    try {
      const res = await api.post('/order', getOrderMetadataPayload(), {
        headers: { Authorization: `Bearer ${token}` },
      });
      setOrderId(String(res.data.orderId ?? ''));
      setResponseData('Новый запроса успешно зарезервирован.');
    } catch (error) {
      handleError(error);
    }
  };

  // Создание нового запроса. Если файлы добавлены, перед отправкой заполняем piev_epgu.xml
  const newOrder = async () => {
    if (!isServiceAvailable()) {
      setStatus(serviceUnavailableReason());
      return;
    }
    if (!hasValidRuntimeRegion()) {
      setStatus('Укажите ОКАТО пользователя: от 2 до 11 цифр.');
      return;
    }
    if (orderId && !isValidOrderId(orderId)) {
      setStatus('Order ID должен быть положительным целым числом.');
      return;
    }
    try {
      const formData = new FormData();
      files.forEach((file) => formData.append('files_upload', file));
      appendXmlDocuments(formData);
      const submissionContext = getSubmissionContext();
      const meta = getOrderMetadataPayload(
        submissionContext === null ? {} : { submissionContext }
      );
      formData.append(
        'meta',
        JSON.stringify(meta)
      );
      const res = await api.post('/push', formData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setOrderId(String(res.data.orderId ?? ''));
      setResponseData('Запрос создан.');
    } catch (e) {
      logError('Ошибка создания запроса:', e);
      setStatus('Ошибка создания запроса.');
    }
  };

  // Создание расширенного запроса (chunked)
  const createOrderExtended = async () => {
    if (!isServiceAvailable()) {
      setStatus(serviceUnavailableReason());
      return;
    }
    if (!hasValidRuntimeRegion()) {
      setStatus('Укажите ОКАТО пользователя: от 2 до 11 цифр.');
      return;
    }
    try {
      if (!isValidOrderId(orderId)) {
        setStatus('Для расширенной отправки требуется корректный Order ID.');
        return;
      }
      const formData = new FormData();
      appendXmlDocuments(formData);
      files.forEach((file) => formData.append('files_upload', file));
      const submissionContext = getSubmissionContext();
      const meta = getOrderMetadataPayload(
        submissionContext === null ? {} : { submissionContext }
      );
      formData.append(
        'meta',
        JSON.stringify(meta)
      );
      formData.append('chunks', '1');
      formData.append('chunk', '0');
      formData.append('orderId', exactOrderId(orderId));
      const res = await api.post('/push/chunked', formData, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setOrderId(String(res.data.orderId ?? ''));
      setResponseData('Расширенный запрос создан.');
    } catch (e) {
      logError('Ошибка создания расширенного запроса:', e);
      setStatus('Ошибка создания расширенного запроса.');
    }
  };

  const submitOrder = async () => {
    if (getSubmissionMode() === 'chunked') {
      await createOrderExtended();
      return;
    }
    await newOrder();
  };

  const previewGoskeyRequest = async (payload) => {
    setGoskeyPreviewing(true);
    try {
      const res = await api.post(GOSKEY_ROUTES.preview, payload);
      if (!res.data?.xml) throw new Error('Backend не вернул req.xml.');
      setXmlDocuments([
        {
          id: 'request',
          name: res.data.fileName || 'req.xml',
          content: res.data.xml,
        },
      ]);
      setSelectedXmlIndex(0);
      setResponseData({
        serviceCode: res.data.serviceCode,
        variant: res.data.variant,
        capability: res.data.capability,
        requiresDetachedSignature: res.data.requiresDetachedSignature,
      });
      setStatus('Предпросмотр req.xml сформирован. Backend повторно создаст его при отправке.');
      setCurrentTab('xml');
    } catch (error) {
      handleError(error);
    } finally {
      setGoskeyPreviewing(false);
    }
  };

  const submitGoskeyRequest = async (payload) => {
    if (!selectedCertId) {
      setStatus('Для подписи Госключа сначала явно выберите сертификат.');
      return;
    }
    if (payload.orderId !== undefined && !isValidOrderId(payload.orderId)) {
      setStatus('Order ID должен быть положительным целым числом.');
      return;
    }
    setGoskeySubmitting(true);
    try {
      const formData = createGoskeySubmissionFormData(payload, files);
      const res = await api.post(GOSKEY_ROUTES.submit, formData);
      if (res.data?.orderId) setOrderId(String(res.data.orderId));
      setResponseData(res.data);
      setStatus(
        `Запрос Госключа отправлен: ${res.data?.transport || 'транспорт не указан'}, ` +
          `подписано файлов: ${res.data?.signedFiles ?? '—'}, частей: ${res.data?.chunks ?? '—'}.`
      );
    } catch (error) {
      handleError(error);
    } finally {
      setGoskeySubmitting(false);
    }
  };

  // Получение деталей запроса
  const getOrderDetails = async (id) => {
    return await api.post(orderRoute(id), null, {
      headers: { Authorization: `Bearer ${token}` },
    });
  };
  const checkOrderDetailsMain = async (id) => {
    if (!isValidOrderId(id)) {
      setStatus('Укажите корректный Order ID: положительное целое число.');
      return;
    }
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
    if (!isValidOrderId(id)) {
      setStatus('Получен некорректный Order ID; запрос не отправлен.');
      return;
    }
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
    if (!isValidOrderId(fileOrderId)) {
      setStatus('Укажите корректный Order ID перед скачиванием.');
      return;
    }
    try {
      const res = await api.post(orderRoute(fileOrderId), null, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const { message, fileDetails } = res.data;
      setStatus(message);
      if (!Array.isArray(fileDetails) || fileDetails.length === 0) return;
      await downloadFilesSequentially(fileDetails, async (file) => {
        const { objectId, objectType, mnemonic, eserviceCode } = file;
        const downloadRes = await api.post(
          `/download_file/${encodeURIComponent(String(objectId))}/${encodeURIComponent(
            String(objectType)
          )}`,
          null,
          {
            headers: { Authorization: `Bearer ${token}` },
            params: { mnemonic, eserviceCode },
            responseType: 'blob',
          }
        );
        saveBlobResponse(downloadRes);
      });
    } catch (e) {
      handleError(e);
    }
  };
  const cancelOrder = async () => {
    if (!isValidOrderId(orderId)) {
      setStatus('Укажите корректный Order ID перед отменой.');
      return;
    }
    try {
      const res = await api.post(orderRoute(orderId, '/cancel'), null, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setStatus(res.data.message);
      setResponseData(res.data.orderDetails);
    } catch (e) {
      handleError(e);
    }
  };

  const fetchUpdatedOrders = async ({
    page = pageNum,
    size = totalRecords,
    since = updatedAfter,
  } = {}) => {
    try {
      setSelectItem();
      // setIsFileAvailable(false);
      setIsFileItemAvailable(false);
      setStatus();
      setResponseStatusItem();
      setResponseTable();
      const params = {
        pageNum: page,
        pageSize: size,
        updatedAfter: moment(since).format('YYYY-MM-DDTHH:mm:ss.SSS'),
      };
      const res = await api.get('/getUpdatedAfter', {
        headers: { Authorization: `Bearer ${token}` },
        params,
      });
      setResponseTable(res?.data?.content);
    } catch (e) {
      if (e.response) {
        logError('Ошибка получения запросов', e);
        setStatus(`Ошибка: ${e.response.data.detail || 'Неизвестная ошибка'}`);
      } else {
        setStatus('Ошибка подключения к серверу.');
      }
    }
  };
  useEffect(() => {
    // Uploaded file bodies are deliberately memory-only for the current page.
    calculateZipSize();
  }, [files]);

  useEffect(() => {
    sessionStorage.setItem('currentTab', currentTab);
  }, [currentTab]);
  useEffect(() => {
    sessionStorage.setItem('orderId', orderId);
  }, [orderId]);

  // При изменении orderId применяем только преобразования выбранного профиля.
  useEffect(() => {
    if (!orderId) return;
    updateXmlDocumentsWithFiles();
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
      // Backend объявляет cert_id query-параметром, тело здесь давало 422
      await api.post('/set_current_certificate', null, { params: { cert_id: certId } });
      sessionStorage.removeItem('token');
      setToken('');
      setTokenVisible(false);
      setSelectedCertId(certId);
      setStatus(`Сертификат ${certId} выбран; прежний токен сброшен.`);
    } catch (e) {
      setStatus('Ошибка установки сертификата.');
    }
  };

  const updateXmlDocuments = useCallback(async (serviceCode, profile) => {
    if (!serviceCode || !profile?.available) return;
    const source = axios.CancelToken.source();
    const requestSequence = xmlRequestGateRef.current.begin(() =>
      source.cancel('Выбрана другая услуга.')
    );
    try {
      const response = await axios.get(`${BACKEND_URL}/xml`, {
        params: { service: serviceCode },
        cancelToken: source.token,
      });
      if (!xmlRequestGateRef.current.isCurrent(requestSequence)) return;

      const submissionContext = toScalarSubmissionContext(
        response.data.submissionContext
      );
      const context = createTemplateContext({
        service: profile,
        submissionContext,
        orderId: '',
      });
      const loadedFiles = buildXmlFilesForService(
        response.data,
        profile,
        context
      );
      if (loadedFiles.length === 0) {
        throw new Error('Не удалось получить XML документы для выбранной услуги.');
      }
      setXmlDocuments(loadedFiles);
      setSelectedXmlIndex(0);
      setStatus('Получены XML выбранной услуги с сервера.');
      if (submissionContext !== null) {
        setServiceSubmissionContexts((previous) => ({
          ...previous,
          [serviceCode]: submissionContext,
        }));
      }
    } catch (error) {
      if (
        !axios.isCancel(error) &&
        xmlRequestGateRef.current.isCurrent(requestSequence)
      ) {
        logError('Ошибка получения XML', error);
        setStatus(error.message || 'Ошибка получения XML с сервера.');
      }
    } finally {
      xmlRequestGateRef.current.finish(requestSequence);
    }
  }, []);

  // При выборе вида услуги меняем XML шаблоны
  useEffect(() => {
    const previousService = selectedServiceRef.current;
    const serviceChanged = previousService !== selectedService;
    if (serviceChanged) {
      xmlRequestGateRef.current.cancel();
      setXmlDocuments([]);
      setSelectedXmlIndex(0);
      if (previousService) setOrderId('');
    }
    selectedServiceRef.current = selectedService;
    const profile = serviceOptions.find(
      (service) => service.serviceCode === selectedService
    );
    if (!profile) return undefined;
    setSelectedSubmissionMode(getDefaultSubmissionMode(profile));
    if (isGoskeyServiceProfile(profile)) {
      xmlRequestGateRef.current.cancel();
      setStatus(
        profile.available
          ? 'Заполните параметры Госключа и сформируйте предпросмотр req.xml.'
          : profile.unavailableReason
      );
      return undefined;
    }
    if (!profile.available) {
      xmlRequestGateRef.current.cancel();
      setStatus(profile.unavailableReason);
      return undefined;
    }
    updateXmlDocuments(selectedService, profile);
    return () => xmlRequestGateRef.current.cancel();
  }, [selectedService, serviceOptions, updateXmlDocuments]);

  const reloadActiveServiceXml = () => {
    const profile = getActiveService();
    xmlRequestGateRef.current.cancel();
    setXmlDocuments([]);
    setSelectedXmlIndex(0);
    if (!profile.available) {
      setStatus(profile.unavailableReason || 'Профиль услуги недоступен.');
      return;
    }
    if (isGoskeyServiceProfile(profile)) {
      setStatus('Сформируйте новый предпросмотр req.xml для Госключа.');
      return;
    }
    updateXmlDocuments(selectedService, profile);
  };

  // При монтировании: получаем сертификаты
  useEffect(() => {
    axios
      .get(`${BACKEND_URL}/services`)
      .then((response) => {
        const services = normalizeServices(response.data);
        setServiceOptions(services);
        setSelectedService((current) =>
          services.some((service) => service.serviceCode === current)
            ? current
            : selectInitialService(services)
        );
      })
      .catch((error) => {
        logError('Ошибка получения услуг', error);
        setServiceOptions([]);
      });
    axios
      .get(`${BACKEND_URL}${GOSKEY_ROUTES.capabilities}`)
      .then((response) => {
        setGoskeyCapabilities(Array.isArray(response.data) ? response.data : []);
      })
      .catch((error) => {
        // The signed service profile remains a fail-closed fallback if this
        // informational endpoint is temporarily unavailable.
        logError('Ошибка получения capability-реестра Госключа', error);
        setGoskeyCapabilities([]);
      });
    const fetchCertificates = async () => {
      try {
        const res = await api.post('/get_certificates');
        const certs = Array.isArray(res.data) ? res.data : [];
        if (certs.length > 0) {
          setCertificates(certs);
          setSelectedCertId('');
        } else {
          setStatus('Нет доступных сертификатов.');
          setCertificates([]);
        }
      } catch (e) {
        logError('Ошибка загрузки сертификатов:', e);
        setStatus('Ошибка загрузки сертификатов.');
        setCertificates([]);
      }
    };
    fetchCertificates();
    purgeLegacyPersistentData();
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

  const activeService = getActiveService();
  const activeServiceUsesGoskey = isGoskeyServiceProfile(activeService);
  const submissionModes = getSubmissionModes(activeService);
  const selectedServiceAvailable = Boolean(activeService.available);
  const chunkedOrderMissing =
    selectedSubmissionMode === 'chunked' && !isValidOrderId(orderId);
  const invalidEnteredOrderId = Boolean(orderId) && !isValidOrderId(orderId);
  const directArchiveTooLarge =
    selectedSubmissionMode === 'push' && zipSize > 50000000;
  const submitDisabled =
    !allowBtn ||
    !selectedServiceAvailable ||
    (!activeServiceUsesGoskey && !hasValidRuntimeRegion()) ||
    invalidEnteredOrderId ||
    directArchiveTooLarge ||
    chunkedOrderMissing;
  const activeTemplateContext = getTemplateContext();
  const renderedDocumentNames = (activeService.documents || []).map((document) =>
    renderTemplateName(document.outputName, activeTemplateContext)
  );
  const renderedArchiveName = renderTemplateName(
    activeService.submission?.archiveNameTemplate || '',
    activeTemplateContext
  );

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
              { key: 'setup', icon: <SettingOutlined />, label: 'Настройка' },
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
                      aria-label="Сертификат подписи"
                      value={selectedCertId}
                      onChange={(value) => setCurrentCertificate(value)}
                      style={{ minWidth: 400 }}
                      placeholder="Выберите сертификат"
                    >
                      {Array.isArray(certificates) && certificates.length > 0 ? (
                        certificates.map((cert) => (
                          <Option key={cert.id} value={cert.id}>
                            {certificateOptionLabel(cert)}
                          </Option>
                        ))
                      ) : (
                        <Option value="" disabled>Сертификаты не найдены</Option>
                      )}
                    </Select>
                  </div>
                  {selectedCertId && (
                    <div data-testid="selected-certificate-details">
                      {certificateDetails(
                        certificates.find((cert) => cert.id === selectedCertId)
                      ).map(({ label, value }) => (
                        <Text key={label} style={{ display: 'block' }}>
                          <Text strong>{label}:</Text> {value}
                        </Text>
                      ))}
                    </div>
                  )}
                  <Space>
                    <Input.Password
                      aria-label="API key"
                      autoComplete="off"
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
                      disabled={!selectedCertId || !apiKey.trim()}
                    >
                      {token ? 'Обновить токен' : 'Получить токен'}
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
                    <Space direction="vertical" size="small" style={{ width: '100%' }}>
                      <Text type="success">Маркер доступа получен и хранится только в текущей сессии.</Text>
                      <Button size="small" onClick={() => setTokenVisible((visible) => !visible)}>
                        {tokenVisible ? 'Скрыть токен' : 'Показать токен'}
                      </Button>
                      {tokenVisible && (
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
                          aria-label="Вид услуги"
                          value={selectedService}
                          onChange={(value) => setSelectedService(value)}
                          style={{ width: '100%' }}
                          placeholder="Выберите услугу"
                        >
                          {Array.isArray(serviceOptions) && serviceOptions.length > 0 ? (
                            serviceOptions.map((opt) => (
                              <Option key={opt.serviceCode} value={opt.serviceCode}>
                                {`${opt.description} — ${opt.serviceCode}${
                                  opt.available ? '' : ' [справочно]'
                                }`}
                              </Option>
                            ))
                          ) : (
                            <Option value="" disabled>Загрузка услуг...</Option>
                          )}
                        </Select>
                      </div>
                      {activeService.serviceCode && (
                        <div
                          data-testid="service-capabilities"
                          style={{
                            padding: 12,
                            border: '1px solid #f0f0f0',
                            borderRadius: 8,
                            background: '#fafafa',
                          }}
                        >
                          <Space direction="vertical" size={6} style={{ width: '100%' }}>
                            <Space wrap>
                              <Tag color={activeService.available ? 'success' : 'warning'}>
                                {activeService.available ? 'Отправка доступна' : 'Только справка'}
                              </Tag>
                              <Tag>Транспорт: {activeService.protocol}</Tag>
                              <Tag>Статус: {activeService.status}</Tag>
                              {activeService.spec?.version && (
                                <Tag>Спецификация: {activeService.spec.version}</Tag>
                              )}
                            </Space>
                            {activeService.agency && <Text>{activeService.agency}</Text>}
                            {(activeService.spec?.published || activeService.spec?.source) && (
                              <Text type="secondary">
                                {activeService.spec.published &&
                                  `Опубликовано: ${activeService.spec.published}. `}
                                {activeService.spec.source && (
                                  <a
                                    href={activeService.spec.source}
                                    target="_blank"
                                    rel="noreferrer"
                                  >
                                    Открыть спецификацию
                                  </a>
                                )}
                              </Text>
                            )}
                            {!activeService.available && (
                              <Text type="danger">{activeService.unavailableReason}</Text>
                            )}
                            {renderedDocumentNames.length > 0 && (
                              <Text type="secondary">
                                Файлы: {renderedDocumentNames.join(', ')}
                              </Text>
                            )}
                            {renderedArchiveName && (
                              <Text type="secondary">Архив: {renderedArchiveName}</Text>
                            )}
                            <Space wrap>
                              <Text>Способ отправки:</Text>
                              {activeServiceUsesGoskey ? (
                                <Tag>adaptive — выбирает backend</Tag>
                              ) : submissionModes.length > 1 ? (
                                <Select
                                  aria-label="Способ отправки"
                                  value={selectedSubmissionMode}
                                  onChange={setSelectedSubmissionMode}
                                  style={{ minWidth: 150 }}
                                  options={submissionModes.map((mode) => ({
                                    value: mode,
                                    label: mode,
                                  }))}
                                />
                              ) : (
                                <Tag>{selectedSubmissionMode}</Tag>
                              )}
                            </Space>
                          </Space>
                        </div>
                      )}
                      {!activeServiceUsesGoskey && (
                        <Input
                          aria-label="Регион ОКАТО пользователя"
                          placeholder="ОКАТО пользователя: от 2 до 11 цифр"
                          value={runtimeRegion}
                          onChange={(e) =>
                            setRuntimeRegion(e.target.value.replace(/\D/g, ''))
                          }
                          maxLength={11}
                          status={
                            runtimeRegion && !hasValidRuntimeRegion()
                              ? 'error'
                              : undefined
                          }
                          style={{ width: '100%' }}
                        />
                      )}
                      <Input
                        aria-label="Order ID запроса"
                        placeholder={
                          activeServiceUsesGoskey
                            ? 'Order ID необязателен; указанное значение включает chunked'
                            : 'Введите Order ID запроса'
                        }
                        value={orderId}
                        onChange={(e) => setOrderId(e.target.value)}
                        status={invalidEnteredOrderId ? 'error' : undefined}
                        style={{ width: '100%' }}
                      />
                      {invalidEnteredOrderId && (
                        <Text type="danger">
                          Order ID должен быть положительной десятичной строкой без пробелов и `/`.
                        </Text>
                      )}
                      {activeServiceUsesGoskey ? (
                        <>
                          <GoskeyForm
                            service={activeService}
                            capabilityRegistry={goskeyCapabilities}
                            files={files}
                            orderId={orderId}
                            previewing={goskeyPreviewing}
                            submitting={goskeySubmitting}
                            signingCertificateSelected={Boolean(selectedCertId)}
                            onPreview={previewGoskeyRequest}
                            onSubmit={submitGoskeyRequest}
                          />
                          <Space wrap>
                            <Button
                              danger
                              icon={<CloseCircleOutlined />}
                              onClick={cancelOrder}
                              disabled={!isValidOrderId(orderId)}
                            >
                              Отменить запрос
                            </Button>
                            <Button
                              icon={<SearchOutlined />}
                              onClick={() => checkOrderDetailsMain(orderId)}
                              disabled={!isValidOrderId(orderId)}
                            >
                              Проверить статус
                            </Button>
                          </Space>
                          <Text type="secondary">
                            Оценка ZIP исходных документов без req.xml и .sig:{' '}
                            {(zipSize / (1024 * 1024)).toFixed(2)} MB
                          </Text>
                        </>
                      ) : (
                        <>
                          <Space wrap>
                            <Button
                              type="primary"
                              icon={<PlusOutlined />}
                              onClick={reserveOrder}
                              disabled={
                                !allowBtn ||
                                !selectedServiceAvailable ||
                                !hasValidRuntimeRegion()
                              }
                              title={
                                selectedServiceAvailable
                                  ? undefined
                                  : activeService.unavailableReason
                              }
                            >
                              Зарезервировать
                            </Button>
                            <Button
                              type="primary"
                              icon={<SendOutlined />}
                              onClick={submitOrder}
                              disabled={submitDisabled}
                              title={
                                !selectedServiceAvailable
                                  ? activeService.unavailableReason
                                  : chunkedOrderMissing
                                    ? 'Сначала зарезервируйте Order ID.'
                                    : directArchiveTooLarge
                                      ? 'Прямая /push-отправка ограничена 50 MB; выберите chunked.'
                                      : undefined
                              }
                              style={{ background: !submitDisabled ? '#52c41a' : undefined }}
                            >
                              {getSubmissionMode() === 'chunked'
                                ? 'Создать запрос (chunked)'
                                : 'Создать запрос'
                              }
                            </Button>
                            <Button
                              danger
                              icon={<CloseCircleOutlined />}
                              onClick={cancelOrder}
                              disabled={!isValidOrderId(orderId)}
                            >
                              Отменить
                            </Button>
                            <Button
                              icon={<SearchOutlined />}
                              onClick={() => checkOrderDetailsMain(orderId)}
                              disabled={!isValidOrderId(orderId)}
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
                            disabled={!selectedServiceAvailable}
                          >
                            Заполнить XML
                          </Button>
                        </>
                      )}
                    </Space>
                  </Col>
                  <Col xs={24} lg={12}>
                    <Space direction="vertical" size="middle" style={{ width: '100%', height: '100%' }}>
                      <Button
                        type="primary"
                        icon={<DownloadOutlined />}
                        onClick={() => downloadOrderFile(orderId)}
                        disabled={!isFileAvailable || !isValidOrderId(orderId)}
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
                <Button
                  danger
                  icon={<DeleteOutlined />}
                  onClick={clearSensitiveLocalData}
                  style={{ marginTop: 12 }}
                >
                  Удалить все локальные данные и сессию
                </Button>
              </Card>
            </div>
          )}

          {currentTab === 'setup' && <SetupGuide />}

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
                    <Button
                      icon={<FileTextOutlined />}
                      onClick={() => handleFillXml()}
                      disabled={!selectedServiceAvailable}
                    >
                      Заполнить XML
                    </Button>
                    <Button
                      danger
                      icon={<ClearOutlined />}
                      onClick={reloadActiveServiceXml}
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
                        fetchUpdatedOrders({ page: 0, size: value });
                      }}
                      style={{ width: 80 }}
                    >
                      <Option value={10}>10</Option>
                      <Option value={50}>50</Option>
                      <Option value={100}>100</Option>
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
                    onClick={() => downloadOrderFile(selectItem)}
                    disabled={
                      !isFileItemAvailable ||
                      !isValidOrderId(selectItem)
                    }
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
        {/* Кнопка наверх. Внутри Layout, поэтому доступна на всех вкладках. */}
        <FloatButton.BackTop
          visibilityHeight={200}
          duration={300}
          icon={<VerticalAlignTopOutlined />}
          tooltip="Наверх"
          aria-label="Наверх"
          style={{ right: 32, bottom: 32 }}
        />
      </Layout>
    </ConfigProvider>
  );
}

export default App;
