import { CheckCircleFilled, CloseCircleFilled, QuestionCircleFilled, WarningFilled } from '@ant-design/icons';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Button, IconButton } from '@mui/material';
import { ENTITY_NAME_VM_IMAGE } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import moment from 'moment';
import { useEffect, useState } from 'react';
import configs from './vm-image-config.json';
import VMImageForm from './vm-image-form';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import CustomDatatable from 'components/styledMUI/Datatable';

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

const VMImagePage = ({ title }) => {
    const classes = useStyles();
    const [UUID, setUUID] = useState();
    const [formOpen, setFormOpen] = useState(false);
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');

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
        if (configReshaped.fields[i].label === 'Last seen active') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                if (value) {
                    value = String(new Date(value));
                    value = moment(value).format('MMMM Do YYYY, h:mm:ss a');
                    return <>{value}</>;
                }
            };
        }
    }

    const closeForm = () => {
        setUUID();
        setFormOpen(false);
    };

    const openForm = () => {
        setFormOpen(true);
    };

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.fileInteractionService
                .deleteFile(ENTITY_NAME_VM_IMAGE, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete image successful');
                    } else {
                        setErrorSnackbarMessage('Delete image unsuccessful');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete image unsuccessful');
                });
        }
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <CustomDatatable
                entityName={ENTITY_NAME_VM_IMAGE}
                configs={configReshaped}
                deleteData={deleteData}
                setUUID={setUUID}
                openForm={openForm}
            />
            <VMImageForm
                formOpen={formOpen}
                closeForm={closeForm}
                UUID={UUID}
                setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
            />
            <Button size="medium" variant="contained" color="primary" onClick={() => openForm()} className={classes.button}>
                Add
            </Button>
        </div>
    );
};

export default VMImagePage;
