import configs from './logs-config.json';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { ENTITY_NAME_INVENTORY_LOGS } from 'framework/caching/entity-cache';
import moment from '../../../node_modules/moment/moment';
import { useParams } from 'react-router-dom';
import CustomDatatable from 'components/styledMUI/Datatable';
import { useEffect } from 'react';

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

const InventoryLogsPages = ({ title }) => {
    const classes = useStyles();
    const params = useParams();

    useEffect(() => {
        document.title = title;
    }, []);

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

    return (
        <div className={classes.root}>
            <CustomDatatable entityName={ENTITY_NAME_INVENTORY_LOGS} configs={configReshaped} presetFilterValue={params.UUID} />
        </div>
    );
};

export default InventoryLogsPages;
