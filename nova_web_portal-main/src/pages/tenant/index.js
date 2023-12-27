import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Button } from '@mui/material';
import { ENTITY_NAME_TENANT } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import MUIDataTable from 'mui-datatables';
import { useEffect, useState } from 'react';
import ConfirmationDialog from 'components/styledMUI/confirmation-dialog';
import configs from './tenant-config.json';
import TenantForm from './tenant-form';
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

const InventoryPage = ({ title }) => {
    const classes = useStyles();
    const [tenants, setTenants] = useState([]);
    const [UUID, setUUID] = useState();
    const [formOpen, setFormOpen] = useState(false);
    const [deleteUUIDS, setDeleteUUIDS] = useState([]);
    const [confirmDeleteForm, setConfirmDeleteForm] = useState(false);
    const [noOfInstances, setNoOfInstances] = useState(10);
    const [startOfInstances, setStartOfInstances] = useState(0);
    const [tenantsCount, setTenantsCount] = useState(0);
    const [page, setPage] = useState(0);
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');

    useEffect(() => {
        document.title = title;
    }, []);

    var configReshaped = configs;

    useEffect(() => {
        const tenantsSub = serviceFactoryInstance.dataLoaderService
            .dataSub(ENTITY_NAME_TENANT, undefined, noOfInstances, startOfInstances)
            .subscribe((data) => {
                if (data) {
                    setTenants(data);
                }
            });

        return () => {
            tenantsSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache, noOfInstances, startOfInstances]);

    useEffect(() => {
        const tenantsCountSub = serviceFactoryInstance.dataLoaderService.countSub(ENTITY_NAME_TENANT).subscribe((data) => {
            if (data) {
                setTenantsCount(data);
            }
        });

        return () => {
            tenantsCountSub.unsubscribe();
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
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_TENANT, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete tenant successful');
                    } else {
                        setErrorSnackbarMessage('Delete tenant failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete tenant failed');
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
                rowsDeleteUUIDS.push(tenants[rowsDeleted.data[i].dataIndex].UUID);
            }
            setDeleteUUIDS(rowsDeleteUUIDS);
            setConfirmDeleteForm(true);
        },
        onRowClick: (rowData, rowMeta) => {
            setUUID(tenants[rowMeta.dataIndex].UUID);
            openForm();
        },
        count: tenantsCount,
        rowsPerPage: 10,
        rowsPerPageOptions: [10, 25, 50],
        serverSide: true,
        page: page,
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
                    (deleteUUIDS.length > 1 && `Are you sure you want to delete the tenant?`) ||
                    (deleteUUIDS.length === 1 && `Are you sure you want to delete the tenant?`)
                }
                onOK={handleDeleteOK}
                onCancel={handleDeleteCancel}
            />
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />

            <MUIDataTable options={options} data={tenants} columns={configReshaped.fields} />
            <TenantForm
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

export default InventoryPage;
