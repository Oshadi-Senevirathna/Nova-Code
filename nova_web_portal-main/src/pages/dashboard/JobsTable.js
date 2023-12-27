import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import { ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './job-config.json';
import moment from '../../../node_modules/moment/moment';
import MUIDataTable from 'mui-datatables';

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

const JobsTable = () => {
    const classes = useStyles();
    const [jobs, setJobs] = useState();

    useEffect(() => {
        const jobsSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_FRONTEND_JOBS).subscribe((data) => {
            if (data) {
                var date = Date.now();
                var temp = [];
                for (let i = 0; i < data.length; i++) {
                    if (data[i].created_at > date - 604800000) {
                        temp.push(data[i]);
                    }
                }
                setJobs(temp);
            }
        });

        return () => {
            jobsSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

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

    const options = {
        selectableRowsHideCheckboxes: true,
        rowsPerPage: 10,
        rowsPerPageOptions: [10, 25, 50],
        serverSide: false,
        filter: false,
        sort: false,
        download: false,
        selectableRows: false,
        print: false,
        viewColumns: false,
        searchOpen: false,
        search: false
    };

    return (
        <div className={classes.root}>
            <MUIDataTable options={options} data={jobs} columns={configReshaped.fields} />
        </div>
    );
};

export default JobsTable;
