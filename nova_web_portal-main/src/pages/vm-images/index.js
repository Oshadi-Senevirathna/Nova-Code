import { CheckCircleFilled, CloseCircleFilled, QuestionCircleFilled, WarningFilled } from '@ant-design/icons';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Button, IconButton } from '@mui/material';
import { ENTITY_NAME_VM_IMAGE } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import moment from 'moment';
import MUIDataTable from 'mui-datatables';
import { useEffect, useState } from 'react';
import ConfirmationDialog from 'components/styledMUI/confirmation-dialog';
import configs from './vm-image-config.json';
import InventoryForm from './vm-image-form';
import CustomSnackbar from 'components/styledMUI/Snackbar';

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
    const [vmImages, setVMImages] = useState([]);
    const [UUID, setUUID] = useState();
    const [formOpen, setFormOpen] = useState(false);
    const [deleteUUIDS, setDeleteUUIDS] = useState([]);
    const [confirmDeleteForm, setConfirmDeleteForm] = useState(false);
    const [noOfInstances, setNoOfInstances] = useState(10);
    const [startOfInstances, setStartOfInstances] = useState(0);
    const [count, setCount] = useState(0);
    const [page, setPage] = useState(0);
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

    useEffect(() => {
        const vmImageSub = serviceFactoryInstance.dataLoaderService
            .dataSub(ENTITY_NAME_VM_IMAGE, undefined, noOfInstances, startOfInstances)
            .subscribe((data) => {
                if (data) {
                    setVMImages(data);
                }
            });

        return () => {
            vmImageSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache, noOfInstances, startOfInstances]);

    useEffect(() => {
        const vmImagesCountSub = serviceFactoryInstance.dataLoaderService.countSub(ENTITY_NAME_VM_IMAGE).subscribe((data) => {
            if (data) {
                setCount(data);
            }
        });

        return () => {
            vmImagesCountSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

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

    const handleDeleteOK = () => {
        deleteData(deleteUUIDS);
        setConfirmDeleteForm(false);
    };

    const handleDeleteCancel = () => {
        setConfirmDeleteForm(false);
    };

    const options = {
        onRowsDelete: (rowsDeleted, dataRows) => {
            const rowsDeleteUUIDS = [];
            for (let i = 0; i < rowsDeleted.data.length; i++) {
                rowsDeleteUUIDS.push(vmImages[rowsDeleted.data[i].dataIndex].UUID);
            }
            setDeleteUUIDS(rowsDeleteUUIDS);
            setConfirmDeleteForm(true);
        },
        count: count,
        rowsPerPage: 10,
        rowsPerPageOptions: [10, 25, 50],
        serverSide: true,
        page: page,
        onRowClick: (rowData, rowMeta) => {
            setUUID(vmImages[rowMeta.dataIndex].UUID);
            openForm();
        },
        filter: false,
        onChangePage(currentPage) {
            setPage(currentPage);
            setStartOfInstances(currentPage * noOfInstances);
        },
        onChangeRowsPerPage(numberOfRows) {
            setPage(0);
            setStartOfInstances(0);
            setNoOfInstances(numberOfRows);
        }
    };

    return (
        <div className={classes.root}>
            <ConfirmationDialog
                open={confirmDeleteForm}
                title="Delete Confirmation"
                message={
                    (deleteUUIDS.length > 1 && `Are you sure you want to delete the images?`) ||
                    (deleteUUIDS.length === 1 && `Are you sure you want to delete the image?`)
                }
                onOK={handleDeleteOK}
                onCancel={handleDeleteCancel}
            />
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <MUIDataTable options={options} data={vmImages} columns={configReshaped.fields} />
            <InventoryForm
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
