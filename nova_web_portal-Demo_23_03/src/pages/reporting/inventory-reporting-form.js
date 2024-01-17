import MUIDataTable from 'mui-datatables';
import { useEffect, useState, useRef } from 'react';
import logo from '../../assets/images/logo.png';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { ENTITY_NAME_DEVICE } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './inventory-config.json';
import {
    Button,
    Box,
    Grid,
    Card,
    CardContent,
    MenuItem,
    TextField,
    Typography,
    FormControlLabel,
    FormGroup,
    Checkbox,
    Paper,
    IconButton
} from '@mui/material';
import { useReactToPrint } from 'react-to-print';
import AdapterMoment from '@mui/lab/AdapterMoment';
import LocalizationProvider from '@mui/lab/LocalizationProvider';
import DateTimePicker from '@mui/lab/DateTimePicker';
import moment from '../../../node_modules/moment/moment';
import { CheckCircleFilled, CloseCircleFilled, QuestionCircleFilled, WarningFilled } from '@ant-design/icons';
import { drop } from 'lodash';
import jsPDF from 'jspdf';
import html2pdf from 'html2pdf.js';

const useStyles = makeStyles((theme) => ({
    root: {
        flexGrow: 1,
        width: '96%',
        marginTop: '2%',
        marginLeft: 'auto',
        marginRight: 'auto'
    },
    progressBar: {
        marginTop: '20px',
        marginBottom: '20px',
        marginRight: '20px'
    },
    button: { marginRight: '20px' },
    heading: {
        fontSize: 20,
        paddingBottom: 15
    },
    subheading: {
        fontSize: 18
    },
    disable: {
        backgroundColor: '#f5f5f5'
    }
}));

const InventoryReportingForm = ({ module, cache }) => {
    const classes = useStyles();
    const [dropdownValues, setDropdownValues] = useState({});
    const [deviceLinDist, setDeviceLinDist] = useState('all');
    const [vnfCategory, setVnfCategory] = useState('all');
    const [hyperVisor, setHyperVisor] = useState('all');
    const [os_version, setOs_version] = useState('all');
    const [deviceActiveStatus, setdeviceActiveStatus] = useState('all');
    const [ipRangeStartInput, setIpRangeStartInput] = useState('0.0.0.0');
    const [ipRangeEndInput, setIpRangeEndInput] = useState('255.255.255.255');
    const [ip0, setIp0] = useState(0);
    const [ip1, setIp1] = useState(0);
    const [ip2, setIp2] = useState(0);
    const [ip3Start, setIp3Start] = useState(0);
    const [ip3End, setIp3End] = useState(0);
    const [useIPFilter, setUseIPFilter] = useState(false);
    const [instances, setInstances] = useState([]);
    const [filterSuccess, setFilterSuccess] = useState(false);
    const [filterLabel, setFilterLabel] = useState([]);
    const [reportName, setReportName] = useState('Inventory Report');
    const myRef = useRef(null);

    const [useTimeFilter, setUseTimeFilter] = useState(false);
    const [startTime, setStartTime] = useState(new Date());
    const [endTime, setEndTime] = useState(new Date());
    const [tenant, setTenant] = useState();

    useEffect(() => {
        const tenantSub = serviceFactoryInstance.authService.getTenantObservable().subscribe((tenant) => {
            setTenant(tenant);
        });
        return () => {
            tenantSub.unsubscribe();
        };
    }, [serviceFactoryInstance.authService]);

    useEffect(() => {
        var dropdowns = {};
        dropdowns['linux_distribution'] = ['all'];
        dropdowns['category'] = ['all'];
        dropdowns['hypervisor'] = ['all'];
        dropdowns['os_version'] = ['all'];
        dropdowns['deviceActive_status'] = ['all', 'Online', 'Offline'];

        setDropdownValues(dropdowns);
        serviceFactoryInstance.dataLoaderService.getFieldValues(ENTITY_NAME_DEVICE, 'linux_distribution').then((data) => {
            dropdowns['linux_distribution'] = ['all', ...data.instances];
            serviceFactoryInstance.dataLoaderService.getFieldValues('inventory_vm', 'category').then((data) => {
                dropdowns['category'] = ['all', ...data.instances];
                serviceFactoryInstance.dataLoaderService.getFieldValues('device', 'hypervisor').then((data) => {
                    dropdowns['hypervisor'] = ['all', ...data.instances];
                    serviceFactoryInstance.dataLoaderService.getFieldValues('device', 'os_version').then((data) => {
                        dropdowns['os_version'] = ['all', ...data.instances];
                        serviceFactoryInstance.dataLoaderService.getFieldValues('inventory_vm', 'status').then((data) => {
                            dropdowns['deviceActive_status'] = ['all', 'Online', 'Offline'];
                            setDropdownValues(dropdowns);
                        });
                    });
                });
            });
        });
    }, []);

    var configReshaped = configs;
    for (let i = 0; i < configReshaped.fields.length; i++) {
        if (configReshaped.fields[i].label === 'Online') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                var date = Date.now();
                if (value && value >= date - 180000) {
                    return (
                        <IconButton sx={{ color: 'success.main' }} size="large">
                            <CheckCircleFilled />
                        </IconButton>
                    );
                } else if (value && value < date - 180000 && value >= date - 300000) {
                    return (
                        <IconButton sx={{ color: 'warning.main' }} size="large">
                            <WarningFilled />
                        </IconButton>
                    );
                } else if (value && value < date - 300000) {
                    return (
                        <IconButton sx={{ color: 'error.main' }} size="large">
                            <CloseCircleFilled />
                        </IconButton>
                    );
                } else {
                    return (
                        <IconButton sx={{ color: 'secondary.main' }} size="large">
                            <QuestionCircleFilled />
                        </IconButton>
                    );
                }
            };
        }
        if (configReshaped.fields[i].label === 'Last active') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                if (value) {
                    value = String(new Date(value));
                    value = moment(value).format('DD/MM/YYYY h:mm');
                    return <>{value}</>;
                }
            };
        }
        if (configReshaped.fields[i].label === 'Username') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                if (value) {
                    console.log(value);
                    return <>{value.username}</>;
                }
            };
        }
    }

    const onClearFilter = (event) => {
        setDeviceLinDist('all');
        setVnfCategory('all');
        setHyperVisor('all');
        setOs_version('all');
        setIpRangeEndInput('255.255.255.255');
        setIpRangeStartInput('0.0.0.0');
        setdeviceActiveStatus('all');
    };

    const onDownloadPDF = () => {
        const pdf = new jsPDF();

        const content = myRef.current;

        html2pdf(content, {
            margin: 10,
            filename: 'Inventory Report.pdf',
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
        });
    };
    const onRunFilter = (event) => {
        var temp = [];

        var fields = [];
        var values = [];
        var direction = [];

        var fieldsVM = [];
        var valuesVM = [];
        var directionVM = [];

        if (hyperVisor !== 'all') {
            fields.push(`"hypervisor"`);
            values.push(`"${hyperVisor}"`);
            direction.push(`"0"`);
            temp.push(`Hypervisor : ${hyperVisor}`);
        } else {
            temp.push(`Hypervisor : Any`);
        }

        if (os_version !== 'all') {
            fields.push(`"os_version"`);
            values.push(`"${os_version}"`);
            direction.push(`"0"`);
            temp.push(`os_version : ${os_version}`);
        } else {
            temp.push(`os_version : Any`);
        }

        if (deviceActiveStatus.toLowerCase() !== 'all') {
            fieldsVM.push(`"status"`);
            valuesVM.push(`"${deviceActiveStatus.toLowerCase() === 'online' ? 'UP' : 'DOWN'}"`);
            directionVM.push(`"0"`);
            temp.push(`status : ${deviceActiveStatus}`);
        } else {
            temp.push(`status : Any`);
        }

        // IP Address Range Filtering
        if (useIPFilter) {
            if (ipRangeStartInput && ipRangeEndInput) {
                fields.push(`"ip_address"`);
                values.push(`{"$gte": "${ipRangeStartInput}", "$lte": "${ipRangeEndInput}"}`);
                direction.push(`"between"`);
                temp.push(`IP Address Range: ${ipRangeStartInput} - ${ipRangeEndInput}`);
            } else if (ipRangeStartInput) {
                fields.push(`"ip_address"`);
                values.push(`{"$gte": "${ipRangeStartInput}"}`);
                direction.push(`">="`);
                temp.push(`IP Address Range: >= ${ipRangeStartInput}`);
            } else if (ipRangeEndInput) {
                fields.push(`"ip_address"`);
                values.push(`{"$lte": "${ipRangeEndInput}"}`);
                direction.push(`"<="`);
                temp.push(`IP Address Range: <= ${ipRangeEndInput}`);
            }
        }

        if (deviceLinDist !== 'all') {
            fields.push(`"linux_distribution"`);
            values.push(`"${deviceLinDist}"`);
            direction.push(`"0"`);
            temp.push(`Device linux distribution : ${deviceLinDist}`);
        } else {
            temp.push(`Device linux distribution : Any`);
        }

        if (vnfCategory !== 'all') {
            fieldsVM.push(`"category"`);
            valuesVM.push(`"${vnfCategory}"`);
            directionVM.push(`"0"`);
            temp.push(`VNF Category : ${vnfCategory}`);
        } else {
            temp.push(`VNF Category : Any`);
        }

        if (useTimeFilter) {
            fieldsVM.push(`"onboard_time"`);
            valuesVM.push(`"${moment(startTime).unix() * 1000}"`);
            directionVM.push(`"1"`);
            temp.push(`VNF onboarded after : ${startTime}`);
            fieldsVM.push(`"onboard_time"`);
            valuesVM.push(`"${moment(endTime).unix() * 1000}"`);
            directionVM.push(`"-1"`);
            console.log(valuesVM);
            temp.push(`VNF onboarded before : ${endTime}`);
        }
        setFilterLabel(temp);
        console.log(tenant);

        serviceFactoryInstance.dataLoaderService
            .getFilteredAndSortedInstances(
                ENTITY_NAME_DEVICE,
                undefined,
                undefined,
                undefined,
                undefined,
                `[${fields}]`,
                `[${values}]`,
                `[${direction}]`,
                false,
                tenant
            )
            .then((data) => {
                console.log('Data from database', data);
                if (data.status) {
                    var tempDevices = data.instances;
                    if (fieldsVM.length > 0) {
                        serviceFactoryInstance.dataLoaderService
                            .getFilteredAndSortedInstances(
                                'inventory_vm',
                                undefined,
                                undefined,
                                undefined,
                                undefined,
                                `[${fieldsVM}]`,
                                `[${valuesVM}]`,
                                `[${directionVM}]`
                            )
                            .then((data) => {
                                if (data.status) {
                                    var devicesList = [];
                                    var tempVMs = data.instances;
                                    console.log(tempVMs);
                                    for (let i = 0; i < tempVMs.length; i++) {
                                        for (let j = 0; j < tempDevices.length; j++) {
                                            if (tempVMs[i].device_id === tempDevices[j].UUID && devicesList.indexOf(tempDevices[j]) < 0) {
                                                console.log(tempDevices[j]);
                                                devicesList.push(tempDevices[j]);
                                            }
                                        }
                                    }
                                    setFilterSuccess(true);
                                    setInstances(devicesList);
                                } else {
                                    setFilterSuccess(false);
                                    setInstances([]);
                                }
                            });
                    } else {
                        setFilterSuccess(true);
                        setInstances(data.instances);
                    }
                } else {
                    setFilterSuccess(false);
                    setInstances([]);
                }
            });
    };

    const onChangeFilterValue = (stateSet, event) => {
        stateSet(event.target.value.toString());
    };

    const onChangeIPValue = (stateSet, event, start3, end3) => {
        var temp = parseInt(event.target.value);
        if (!isNaN(temp)) {
            if (start3 && ip3End < temp) {
                if (temp <= 255) {
                    setIp3End(temp);
                } else {
                    setIp3End(255);
                }
            }
            if (end3 && temp < ip3Start) {
                temp = ip3Start;
            }

            if (temp <= 255) {
                stateSet(temp);
            } else {
                stateSet(255);
            }
        } else {
            stateSet(0);
        }
    };

    const options = {
        selectableRowsHideCheckboxes: true,
        pagination: false,
        serverSide: false,
        filter: false,
        sort: false,
        download: false,
        selectableRows: false,
        print: false,
        viewColumns: false,
        searchOpen: false,
        search: false,
        responsive: false
    };

    return (
        <div className={classes.root}>
            <Card>
                <CardContent>
                    <Typography className={classes.heading}>Filter Parameters</Typography>
                    <>
                        <FormGroup>
                            <FormControlLabel
                                control={
                                    <Checkbox
                                        checked={useTimeFilter}
                                        onChange={() => {
                                            setUseTimeFilter(!useTimeFilter);
                                        }}
                                    />
                                }
                                label="Filter with VNF onboarded time period"
                            />
                        </FormGroup>

                        {useTimeFilter && (
                            <>
                                <div style={{ width: '45%', display: 'inline-flex', padding: '10px' }}>
                                    <div style={{ width: '50%' }}>
                                        <Typography>Start time</Typography>
                                    </div>
                                    <div style={{ width: '50%', float: 'right' }}>
                                        <LocalizationProvider dateAdapter={AdapterMoment}>
                                            <DateTimePicker
                                                renderInput={(props) => <TextField {...props} />}
                                                value={startTime}
                                                onChange={(newValue) => {
                                                    setStartTime(newValue);
                                                }}
                                            />
                                        </LocalizationProvider>
                                    </div>
                                </div>
                                <div style={{ width: '45%', display: 'inline-flex', float: 'right', padding: '10px' }}>
                                    <div style={{ width: '50%' }}>
                                        <Typography>End time</Typography>
                                    </div>
                                    <div style={{ width: '50%', float: 'right' }}>
                                        <LocalizationProvider dateAdapter={AdapterMoment}>
                                            <DateTimePicker
                                                renderInput={(props) => <TextField {...props} />}
                                                value={endTime}
                                                onChange={(newValue) => {
                                                    setEndTime(newValue);
                                                }}
                                            />
                                        </LocalizationProvider>
                                    </div>
                                </div>
                            </>
                        )}
                    </>

                    <FormGroup>
                        <FormControlLabel
                            control={
                                <Checkbox
                                    checked={useIPFilter}
                                    onChange={() => {
                                        setUseIPFilter(!useIPFilter);
                                    }}
                                />
                            }
                            label="Filter with IP Address Range"
                        />
                    </FormGroup>

                    {useIPFilter && (
                        <>
                            <div style={{ width: '45%', display: 'inline-flex', padding: '10px' }}>
                                <div style={{ width: '50%' }}>
                                    <Typography>IP Range Start</Typography>
                                </div>
                                <div style={{ width: '50%', float: 'right' }}>
                                    <TextField
                                        value={ipRangeStartInput}
                                        style={{ width: '100%' }}
                                        key={'ipRangeStartInput'}
                                        onChange={(event) => setIpRangeStartInput(event.target.value)}
                                        fullWidth
                                    />
                                </div>
                            </div>
                            <div style={{ width: '45%', display: 'inline-flex', float: 'right', padding: '10px' }}>
                                <div style={{ width: '50%' }}>
                                    <Typography>IP Range End</Typography>
                                </div>
                                <div style={{ width: '50%', float: 'right' }}>
                                    <TextField
                                        value={ipRangeEndInput}
                                        style={{ width: '100%' }}
                                        key={'ipRangeEndInput'}
                                        onChange={(event) => setIpRangeEndInput(event.target.value)}
                                        fullWidth
                                    />
                                </div>
                            </div>
                        </>
                    )}
                    <div style={{ width: '45%', display: 'inline-flex', padding: '10px' }}>
                        <div style={{ width: '50%' }}>
                            <Typography>Linux Distribution</Typography>
                        </div>
                        <div style={{ width: '50%', float: 'right' }}>
                            {dropdownValues && dropdownValues['linux_distribution'] ? (
                                <>
                                    <TextField
                                        value={deviceLinDist || ''}
                                        style={{ width: '100%' }}
                                        key={'linux_distribution'}
                                        select
                                        name={'linux_distribution'}
                                        onChange={(event) => onChangeFilterValue(setDeviceLinDist, event)}
                                        fullWidth
                                    >
                                        {dropdownValues &&
                                            dropdownValues['linux_distribution'] &&
                                            dropdownValues['linux_distribution'].map((option) => (
                                                <MenuItem key={option} value={option}>
                                                    {option}
                                                </MenuItem>
                                            ))}
                                    </TextField>
                                </>
                            ) : (
                                <>
                                    <TextField style={{ width: '100%' }} fullWidth />
                                </>
                            )}
                        </div>
                    </div>
                    <div style={{ width: '45%', display: 'inline-flex', float: 'right', padding: '10px' }}>
                        <div style={{ width: '50%' }}>
                            <Typography>VNF Category</Typography>
                        </div>
                        <div style={{ width: '50%', float: 'right' }}>
                            {dropdownValues && dropdownValues['category'] ? (
                                <>
                                    <TextField
                                        value={vnfCategory || ''}
                                        style={{ width: '100%' }}
                                        key={'category'}
                                        select
                                        name={'category'}
                                        onChange={(event) => onChangeFilterValue(setVnfCategory, event)}
                                        fullWidth
                                    >
                                        {dropdownValues &&
                                            dropdownValues['category'] &&
                                            dropdownValues['category'].map((option) => (
                                                <MenuItem key={option} value={option}>
                                                    {option}
                                                </MenuItem>
                                            ))}
                                    </TextField>
                                </>
                            ) : (
                                <>
                                    <TextField style={{ width: '100%' }} fullWidth />
                                </>
                            )}
                        </div>
                    </div>
                    <div style={{ width: '45%', display: 'inline-flex', float: 'right', padding: '10px' }}>
                        <div style={{ width: '50%' }}>
                            <Typography>Hypervisor</Typography>
                        </div>
                        <div style={{ width: '50%', float: 'right' }}>
                            {dropdownValues && dropdownValues['hypervisor'] ? (
                                <>
                                    <TextField
                                        value={hyperVisor || ''}
                                        style={{ width: '100%' }}
                                        key={'hypervisor'}
                                        select
                                        name={'hypervisor'}
                                        onChange={(event) => onChangeFilterValue(setHyperVisor, event)}
                                        fullWidth
                                    >
                                        {dropdownValues &&
                                            dropdownValues['hypervisor'] &&
                                            dropdownValues['hypervisor'].map((option) => (
                                                <MenuItem key={option} value={option}>
                                                    {option}
                                                </MenuItem>
                                            ))}
                                    </TextField>
                                </>
                            ) : (
                                <>
                                    <TextField style={{ width: '100%' }} fullWidth />
                                </>
                            )}
                        </div>
                    </div>
                    <div style={{ width: '45%', display: 'inline-flex', padding: '10px' }}>
                        <div style={{ width: '50%' }}>
                            <Typography>Os Version</Typography>
                        </div>
                        <div style={{ width: '50%', float: 'right' }}>
                            {dropdownValues && dropdownValues['os_version'] ? (
                                <>
                                    <TextField
                                        value={os_version || ''}
                                        style={{ width: '100%' }}
                                        key={'os_version'}
                                        select
                                        name={'os_version'}
                                        onChange={(event) => onChangeFilterValue(setOs_version, event)}
                                        fullWidth
                                    >
                                        {dropdownValues &&
                                            dropdownValues['os_version'] &&
                                            dropdownValues['os_version'].map((option) => (
                                                <MenuItem key={option} value={option}>
                                                    {option}
                                                </MenuItem>
                                            ))}
                                    </TextField>
                                </>
                            ) : (
                                <>
                                    <TextField style={{ width: '100%' }} fullWidth />
                                </>
                            )}
                        </div>
                    </div>
                    <div style={{ width: '45%', display: 'inline-flex', padding: '10px' }}>
                        <div style={{ width: '50%' }}>
                            <Typography>Status</Typography>
                        </div>
                        <div style={{ width: '50%', float: 'right' }}>
                            {dropdownValues && dropdownValues['deviceActive_status'] ? (
                                <>
                                    <TextField
                                        value={deviceActiveStatus || ''}
                                        style={{ width: '100%' }}
                                        key={'deviceActive_status'}
                                        select
                                        name={'deviceActive_status'}
                                        onChange={(event) => onChangeFilterValue(setdeviceActiveStatus, event)}
                                        fullWidth
                                    >
                                        {dropdownValues &&
                                            dropdownValues['deviceActive_status'] &&
                                            dropdownValues['deviceActive_status'].map((option) => (
                                                <MenuItem key={option} value={option}>
                                                    {option}
                                                </MenuItem>
                                            ))}
                                    </TextField>
                                </>
                            ) : (
                                <>
                                    <TextField style={{ width: '100%' }} fullWidth />
                                </>
                            )}
                        </div>
                    </div>

                    <div style={{ width: '45%', display: 'inline-flex', float: 'right', padding: '10px' }}></div>
                    <br />
                </CardContent>
            </Card>
            <Box display="flex" alignItems="center" className={classes.progressBar}>
                <Button variant="contained" color="primary" className={classes.button} onClick={onRunFilter}>
                    Run Filter
                </Button>
                <Button variant="contained" color="primary" className={classes.button} onClick={onClearFilter}>
                    Clear Filter
                </Button>
                <Button variant="contained" color="primary" className={classes.button} onClick={onDownloadPDF}>
                    Download PDF
                </Button>
            </Box>

            {filterSuccess && (
                <Grid item ref={myRef} display="flex">
                    <Paper variant="elevation" elevation={0} style={{ padding: 40, margin: 'auto' }}>
                        <Grid item>
                            <Grid container direction="row">
                                <Grid item xs={8} align="left">
                                    <Grid container justifyContent="start" alignItems="flex-start" direction="column">
                                        <Typography className={classes.heading}>{reportName}</Typography>
                                        {filterLabel && (
                                            <div>
                                                <Typography className={classes.subheading}>Filters used</Typography>
                                                {filterLabel &&
                                                    filterLabel.map((label) => {
                                                        return <Typography>{label}</Typography>;
                                                    })}
                                                <br />
                                            </div>
                                        )}
                                    </Grid>
                                </Grid>
                                <Grid item xs={4}>
                                    <Grid container direction="column" justifyContent="center" alignItems="flex-end">
                                        <img
                                            src={logo}
                                            align="right"
                                            alt="InSync Login Logo Not Found"
                                            max-height="131px"
                                            height="131px"
                                            width="186px"
                                            max-width="186px"
                                        />
                                    </Grid>
                                </Grid>
                                <br />

                                <div style={{ marginRight: 'auto' }}>
                                    <MUIDataTable options={options} data={instances} columns={configReshaped.fields} />
                                    <br />
                                </div>
                            </Grid>
                        </Grid>
                    </Paper>
                </Grid>
            )}
            <br />
        </div>
    );
};

export default InventoryReportingForm;
