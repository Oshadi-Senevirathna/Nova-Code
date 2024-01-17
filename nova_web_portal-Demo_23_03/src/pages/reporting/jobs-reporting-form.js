import MUIDataTable from 'mui-datatables';
import { useEffect, useState, useRef } from 'react';
import logo from '../../assets/images/logo.png';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './job-config.json';
import {
    Button,
    Box,
    Grid,
    Card,
    CardContent,
    MenuItem,
    TextField,
    Typography,
    Paper,
    FormControlLabel,
    FormGroup,
    Checkbox
} from '@mui/material';
import { useReactToPrint } from 'react-to-print';
import AdapterMoment from '@mui/lab/AdapterMoment';
import LocalizationProvider from '@mui/lab/LocalizationProvider';
import DateTimePicker from '@mui/lab/DateTimePicker';
import moment from '../../../node_modules/moment/moment';

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

const JobsReportingForm = ({ module, cache }) => {
    const classes = useStyles();
    const [dropdownValues, setDropdownValues] = useState({});

    const [jobName, setJobName] = useState('all');
    const [status, setStatus] = useState('all');

    const [instances, setInstances] = useState([]);
    const [filterSuccess, setFilterSuccess] = useState(false);
    const [filterLabel, setFilterLabel] = useState([]);
    const [reportName, setReportName] = useState('Jobs Report');
    const myRef = useRef(null);

    const [useScheduleTimeFilter, setUseScheduleTimeFilter] = useState(false);
    const [startScheduleTime, setStartScheduleTime] = useState(new Date());
    const [endScheduleTime, setEndScheduleTime] = useState(new Date());
    const handleStartScheduleTimeChange = (date) => {
        setStartTime(date);
    };
    const handleEndScheduleTimeChange = (date) => {
        setEndTime(date);
    };

    const [useCompleteTimeFilter, setUseCompleteTimeFilter] = useState(false);
    const [startCompleteTime, setStartCompleteTime] = useState(new Date());
    const [endCompleteTime, setEndCompleteTime] = useState(new Date());
    const handleStartCompleteTimeChange = (date) => {
        setStartTime(date);
    };
    const handleEndCompleteTimeChange = (date) => {
        setEndTime(date);
    };

    useEffect(() => {
        var dropdowns = {};
        dropdowns['job_name'] = ['all'];
        dropdowns['status'] = ['all'];
        setDropdownValues(dropdowns);
        serviceFactoryInstance.dataLoaderService.getFieldValues(ENTITY_NAME_FRONTEND_JOBS, 'job_name').then((data) => {
            dropdowns['job_name'] = ['all', ...data.instances];
            setDropdownValues(dropdowns);
            serviceFactoryInstance.dataLoaderService.getFieldValues(ENTITY_NAME_FRONTEND_JOBS, 'status').then((data) => {
                dropdowns['status'] = ['all', ...data.instances];
                setDropdownValues(dropdowns);
            });
        });
    }, []);

    var configReshaped = configs;
    for (let i = 0; i < configReshaped.fields.length; i++) {
        if (configReshaped.fields[i].label === 'Scheduled at') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                if (value) {
                    value = String(new Date(value));
                    value = moment(value).format('DD/MM/YYYY h:mm');
                    return <>{value}</>;
                }
            };
        }
        if (configReshaped.fields[i].label === 'Completed at') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                if (value) {
                    value = String(new Date(value));
                    value = moment(value).format('DD/MM/YYYY h:mm');
                    return <>{value}</>;
                }
            };
        }
    }

    const onClearFilter = (event) => {
        setJobName('all');
        setStatus('all');
    };

    const onDownloadPDF = useReactToPrint({
        content: () => myRef.current
    });

    const onRunFilter = (event) => {
        var temp = [];

        var fields = [];
        var values = [];
        var direction = [];

        if (jobName !== 'all') {
            fields.push(`"job_name"`);
            values.push(`"${jobName}"`);
            direction.push(`"0"`);
            temp.push(`Job name : ${jobName}`);
        } else {
            temp.push(`Job name : Any`);
        }

        if (status !== 'all') {
            fields.push(`"status"`);
            values.push(`"${status}"`);
            direction.push(`"0"`);
            temp.push(`Status : ${status}`);
        } else {
            temp.push(`Status : Any`);
        }

        if (useScheduleTimeFilter) {
            fields.push(`"scheduled_at"`);
            values.push(`"${moment(startScheduleTime).unix() * 1000}"`);
            direction.push(`"1"`);
            temp.push(`Job scheduled after : ${startScheduleTime}`);
            fields.push(`"scheduled_at"`);
            values.push(`"${moment(endScheduleTime).unix() * 1000}"`);
            direction.push(`"-1"`);
            temp.push(`Job scheduled before : ${endScheduleTime}`);
        }
        if (useCompleteTimeFilter) {
            fields.push(`"completed_at"`);
            values.push(`"${moment(startCompleteTime).unix() * 1000}"`);
            direction.push(`"1"`);
            temp.push(`Job completed after : ${startCompleteTime}`);
            fields.push(`"completed_at"`);
            values.push(`"${moment(endCompleteTime).unix() * 1000}"`);
            direction.push(`"-1"`);
            temp.push(`Job completed before : ${endCompleteTime}`);
        }
        setFilterLabel(temp);

        setFilterLabel(temp);

        serviceFactoryInstance.dataLoaderService
            .getFilteredAndSortedInstances(
                ENTITY_NAME_FRONTEND_JOBS,
                undefined,
                undefined,
                undefined,
                undefined,
                `[${fields}]`,
                `[${values}]`,
                `[${direction}]`
            )
            .then((data) => {
                /* setVms(data.instances); */

                if (data.status) {
                    setFilterSuccess(true);

                    setInstances(data.instances);
                    console.log(data.instances);
                } else {
                    setFilterSuccess(false);
                    setInstances([]);
                }
            });
    };

    const onChangeFilterValue = (stateSet, event) => {
        stateSet(event.target.value.toString());
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
                                        checked={useScheduleTimeFilter}
                                        onChange={() => {
                                            setUseScheduleTimeFilter(!useScheduleTimeFilter);
                                        }}
                                    />
                                }
                                label="Filter with job scheduled time period"
                            />
                        </FormGroup>

                        {useScheduleTimeFilter && (
                            <>
                                <div style={{ width: '45%', display: 'inline-flex', padding: '10px' }}>
                                    <div style={{ width: '50%' }}>
                                        <Typography>Start time</Typography>
                                    </div>
                                    <div style={{ width: '50%', float: 'right' }}>
                                        <LocalizationProvider dateAdapter={AdapterMoment}>
                                            <DateTimePicker
                                                renderInput={(props) => <TextField {...props} />}
                                                value={startScheduleTime}
                                                onChange={(newValue) => {
                                                    setStartScheduleTime(newValue);
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
                                                value={endScheduleTime}
                                                onChange={(newValue) => {
                                                    setEndScheduleTime(newValue);
                                                }}
                                            />
                                        </LocalizationProvider>
                                    </div>
                                </div>
                            </>
                        )}
                    </>
                    <>
                        <FormGroup>
                            <FormControlLabel
                                control={
                                    <Checkbox
                                        checked={useCompleteTimeFilter}
                                        onChange={() => {
                                            setUseCompleteTimeFilter(!useCompleteTimeFilter);
                                        }}
                                    />
                                }
                                label="Filter with job completed time period"
                            />
                        </FormGroup>

                        {useCompleteTimeFilter && (
                            <>
                                <div style={{ width: '45%', display: 'inline-flex', padding: '10px' }}>
                                    <div style={{ width: '50%' }}>
                                        <Typography>Start time</Typography>
                                    </div>
                                    <div style={{ width: '50%', float: 'right' }}>
                                        <LocalizationProvider dateAdapter={AdapterMoment}>
                                            <DateTimePicker
                                                renderInput={(props) => <TextField {...props} />}
                                                value={startCompleteTime}
                                                onChange={(newValue) => {
                                                    setStartCompleteTime(newValue);
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
                                                value={endCompleteTime}
                                                onChange={(newValue) => {
                                                    setEndCompleteTime(newValue);
                                                }}
                                            />
                                        </LocalizationProvider>
                                    </div>
                                </div>
                            </>
                        )}
                    </>
                    <div style={{ width: '45%', display: 'inline-flex', padding: '10px' }}>
                        <div style={{ width: '50%' }}>
                            <Typography>Job Name</Typography>
                        </div>
                        <div style={{ width: '50%', float: 'right' }}>
                            {dropdownValues && dropdownValues['job_name'] ? (
                                <>
                                    <TextField
                                        value={jobName || ''}
                                        style={{ width: '100%' }}
                                        key={'job_name'}
                                        select
                                        name={'job_name'}
                                        onChange={(event) => onChangeFilterValue(setJobName, event)}
                                        fullWidth
                                    >
                                        {dropdownValues &&
                                            dropdownValues['job_name'] &&
                                            dropdownValues['job_name'].map((option) => (
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
                            {dropdownValues && dropdownValues['status'] ? (
                                <>
                                    <TextField
                                        value={status || ''}
                                        style={{ width: '100%' }}
                                        key={'status'}
                                        select
                                        name={'status'}
                                        onChange={(event) => onChangeFilterValue(setStatus, event)}
                                        fullWidth
                                    >
                                        {dropdownValues &&
                                            dropdownValues['status'] &&
                                            dropdownValues['status'].map((option) => (
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
                    <Paper variant="elevation" elevation={0} style={{ padding: 40, width: '1100px', maxWidth: '1100px', margin: 'auto' }}>
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

                                <div style={{ marginRight: 'auto', width: '100%' }}>
                                    <MUIDataTable options={options} data={instances} columns={configs.fields} />
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

export default JobsReportingForm;
