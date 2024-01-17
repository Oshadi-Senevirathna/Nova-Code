import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './job-config.json';
import ConfirmationDialog from 'components/styledMUI/confirmation-dialog';
import CustomDatatable from 'components/styledMUI/Datatable';
import moment from '../../../node_modules/moment/moment';

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

const JobsPage = ({ title }) => {
    const classes = useStyles();
    const navigate = useNavigate();
    const [deleteUUIDS, setDeleteUUIDS] = useState([]);
    const [confirmDeleteForm, setConfirmDeleteForm] = useState(false);
    const [UUID, setUUID] = useState();
    const [jobsSummary, setjobsSummary] = useState();

    var configReshaped = configs;
    for (let i = 0; i < configReshaped.fields.length; i++) {
        if (configReshaped.fields[i].label === 'Created at') {
            configReshaped.fields[i].options.customBodyRender = (value, tableMeta, updateValue) => {
                if (value) {
                    value = String(new Date(value));
                    value = moment(value).format('DD/MM/YYYY h:mm');
                    return <>{value}</>;
                }
            };
        }
    }

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        const jobsSummarySub = serviceFactoryInstance.dataLoaderService
            .dataSub(`${ENTITY_NAME_FRONTEND_JOBS}>dashboard>job`)
            .subscribe((data) => {
                if (data) {
                    setjobsSummary(data);
                }
            });

        return () => {
            jobsSummarySub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const getSummary = () => {
        const numberWithCommas = (x) => {
            if (x === undefined || x === null) {
                return '0';
            }
            return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        };
        var jobPicked = 0;
        var notStarted = 0;
        var completed = 0;
        var failed = 0;
        var running = 0;
        var total = 0;

        for (let i = 0; i < jobsSummary.labels.length; i++) {
            total += jobsSummary.series[i];
            if (jobsSummary.labels[i] === 'JOB_PICKED') {
                jobPicked = jobsSummary.series[i];
            }
            if (jobsSummary.labels[i] === 'NOT_STARTED') {
                notStarted = jobsSummary.series[i];
            }
            if (jobsSummary.labels[i] === 'COMPLETED') {
                completed = jobsSummary.series[i];
            }
            if (jobsSummary.labels[i] === 'FAILED') {
                failed = jobsSummary.series[i];
            }
            if (jobsSummary.labels[i] === 'RUNNING') {
                running = jobsSummary.series[i];
            }
        }

        return [
            { heading: 'Not started', value: numberWithCommas(notStarted) },
            { heading: 'Picked', value: numberWithCommas(jobPicked) },
            { heading: 'Running', value: numberWithCommas(running) },
            { heading: 'Completed', value: numberWithCommas(completed) },
            { heading: 'Failed', value: numberWithCommas(failed) },
            { heading: 'Total Jobs', value: numberWithCommas(total) }
        ];
    };

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_FRONTEND_JOBS, UUID)
                .then((data) => {
                    if (data.status) {
                        console.debug('Delete job successful');
                    } else {
                        console.debug('Delete job failed');
                    }
                })
                .catch((reason) => {
                    console.debug('Delete job failed');
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

    const navigateToPage = (param) => {
        navigate(`/jobs/details/${param}`);
    };

    return (
        <div className={classes.root}>
            <ConfirmationDialog
                open={confirmDeleteForm}
                title="Delete Confirmation"
                message={
                    (deleteUUIDS.length > 1 && `Are you sure you want to delete the tasks?`) ||
                    (deleteUUIDS.length === 1 && `Are you sure you want to delete the task?`)
                }
                onOK={handleDeleteOK}
                onCancel={handleDeleteCancel}
            />
            <CustomDatatable
                entityName={ENTITY_NAME_FRONTEND_JOBS}
                configs={configReshaped}
                deleteData={deleteData}
                setUUID={setUUID}
                navigateToPage={navigateToPage}
                summary={jobsSummary && getSummary()}
                filter={true}
            />
        </div>
    );
};

export default JobsPage;
