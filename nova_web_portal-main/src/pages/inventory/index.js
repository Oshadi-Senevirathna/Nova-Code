import { CheckCircleFilled, CloseCircleFilled, QuestionCircleFilled, WarningFilled } from '@ant-design/icons';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Button, IconButton } from '@mui/material';
import { ENTITY_NAME_DEVICE, ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import moment from 'moment';
import { useEffect, useState } from 'react';
import configs from './inventory-config.json';
import InventoryForm from './inventory-form';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import CustomDatatable from 'components/styledMUI/Datatable';
import UserForm from './user-form';
import { useNavigate } from 'react-router-dom';

const useStyles = makeStyles((theme) => ({
    root: {
        flexGrow: 1,
        width: '100%',
        margin: 0,
        padding: 0
    },
    progressBar: {
        marginTop: '20px',
        marginBottom: '20px',
        marginRight: '20px'
    },
    button: {
        marginRight: '20px',
        marginTop: '10px',
        width: '120px'
    },
    iconbutton: {
        marginRight: '20px',
        marginTop: '10px',
        width: '30px'
    }
}));

const InventoryPage = ({ title }) => {
    const classes = useStyles();
    const [UUID, setUUID] = useState();
    const [formOpen, setFormOpen] = useState(false);
    const [userFormOpen, setUserFormOpen] = useState(false);
    const [deviceSummary, setDeviceSummary] = useState();
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');
    const navigate = useNavigate();
    const [tenant, setTenant] = useState();

    useEffect(() => {
        const tenantSub = serviceFactoryInstance.authService.getTenantObservable().subscribe((tenant) => {
            setTenant(tenant);
        });
        return () => {
            tenantSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    useEffect(() => {
        document.title = title;
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
                if (value && value.username) {
                    return (
                        <>
                            <Button sx={{ textTransform: 'none' }} onClick={() => openUserForm(tableMeta.rowData[0])}>
                                {value.username}
                            </Button>
                        </>
                    );
                } else {
                    return (
                        <>
                            <Button onClick={() => openUserForm(tableMeta.rowData[0])}>Create Username</Button>
                        </>
                    );
                }
            };
        }
        if (configReshaped.fields[i].label === 'Hostname') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                if (value) {
                    return (
                        <>
                            <Button sx={{ textTransform: 'none' }} onClick={() => navigate(`/inventory/details/${tableMeta.rowData[0]}`)}>
                                {value}
                            </Button>
                        </>
                    );
                }
            };
        }
    }

    useEffect(() => {
        const devicesSummarySub = serviceFactoryInstance.dataLoaderService
            .dataSub(`${ENTITY_NAME_DEVICE}>dashboard>device_status`)
            .subscribe((data) => {
                if (data) {
                    setDeviceSummary(data.series);
                }
            });

        return () => {
            devicesSummarySub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const closeForm = () => {
        setUUID();
        setFormOpen(false);
    };

    const openForm = () => {
        setFormOpen(true);
    };

    const closeUserForm = () => {
        setUUID();
        setFormOpen(false);
        setUserFormOpen(false);
    };

    const openUserForm = (value) => {
        setUUID(value);
        setUserFormOpen(true);
    };

    const getSummary = () => {
        const numberWithCommas = (x) => {
            if (x === undefined || x === null) {
                return '0';
            }
            return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        };

        return [
            { heading: 'Total Devices', value: numberWithCommas(deviceSummary[0] + deviceSummary[1] + deviceSummary[2]) },
            { heading: 'Offline', value: numberWithCommas(deviceSummary[0] + deviceSummary[1]) },
            { heading: 'Online', value: numberWithCommas(deviceSummary[2]) }
        ];
    };

    const discover = () => {
        var job = {};
        var args = [];
        job.job_name = 'simple_division_job_new';
        args.push(10);
        args.push(2);
        job.arguments = args;
        serviceFactoryInstance.dataLoaderService
            .addInstance(ENTITY_NAME_FRONTEND_JOBS, job)
            .then((data) => {
                if (data.status) {
                    setSuccessSnackbarMessage('Created discover job');
                } else {
                    setErrorSnackbarMessage('Create discover job failed');
                }
            })
            .catch((reason) => {
                setErrorSnackbarMessage('Create discover job failed');
            });
    };

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_DEVICE, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete device successful');
                    } else {
                        setErrorSnackbarMessage('Delete device failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete device failed');
                });
        }
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <CustomDatatable
                entityName={ENTITY_NAME_DEVICE}
                tenant={tenant}
                configs={configReshaped}
                deleteData={deleteData}
                setUUID={setUUID}
                openForm={openForm}
                summary={deviceSummary && getSummary()}
            />
            <InventoryForm
                formOpen={!userFormOpen && formOpen}
                closeForm={closeForm}
                UUID={UUID}
                setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
            />
            <UserForm
                formOpen={userFormOpen}
                closeForm={closeUserForm}
                UUID={UUID}
                setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
            />
            <br />
            <Button fullWidth size="large" type="submit" variant="contained" color="primary" onClick={() => openForm()}>
                Add
            </Button>
            {/* <Button size="medium" variant="contained" color="primary" onClick={() => discover()} className={classes.button}>
                Discover
            </Button> */}
        </div>
    );
};

export default InventoryPage;
