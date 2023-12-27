import { useEffect, useState } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './logs-config.json';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Typography } from '../../../node_modules/@mui/material/index';
import { ENTITY_NAME_LOGS_USER } from 'framework/caching/entity-cache';
import MUIDataTable from 'mui-datatables';
import moment from '../../../node_modules/moment/moment';

const useStyles = makeStyles((theme) => ({
    root: {
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
        fontWeight: 'bold',
        paddingBottom: 15
    }
}));

const LogsPages = () => {
    const classes = useStyles();
    const [instances, setInstances] = useState([]);

    const [noOfInstances, setNoOfInstances] = useState(10);
    const [startOfInstances, setStartOfInstances] = useState(0);
    const [count, setCount] = useState(0);
    const [page, setPage] = useState(0);

    var configReshaped = configs;
    for (let i = 0; i < configReshaped.fields.length; i++) {
        if (configReshaped.fields[i].name === 'timestamp') {
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
        const logsSub = serviceFactoryInstance.dataLoaderService
            .dataSub(ENTITY_NAME_LOGS_USER, undefined, noOfInstances, startOfInstances)
            .subscribe((data) => {
                if (data) {
                    setInstances(data);
                }
            });

        return () => {
            logsSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache, noOfInstances, startOfInstances]);

    useEffect(() => {
        const logsCountSub = serviceFactoryInstance.dataLoaderService.countSub(ENTITY_NAME_LOGS_USER).subscribe((data) => {
            if (data) {
                setCount(data);
            }
        });

        return () => {
            logsCountSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const options = {
        selectableRowsHideCheckboxes: true,
        count: count,
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
            <Typography className={classes.heading}>{configReshaped.name}</Typography>
            <div style={{ marginRight: 20 }}>
                <MUIDataTable options={options} data={instances} columns={configReshaped.fields} />
            </div>
        </div>
    );
};

export default LogsPages;
