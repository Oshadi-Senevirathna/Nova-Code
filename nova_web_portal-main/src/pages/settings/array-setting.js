import { IconButton } from '@mui/material';
import { TextField, Typography } from '../../../node_modules/@mui/material/index';
import { useEffect, useState } from 'react';
import { PlusCircleOutlined, MinusCircleOutlined } from '@ant-design/icons';

export default function ArraySetting(props) {
    const [value, setValue] = useState([]);

    useEffect(() => {
        setValue(props.setting.data.value !== undefined ? props.setting.data.value : props.setting.data.defaultValue);
    }, [props.setting.data.value, props.setting.data.defaultValue]);

    const insert = (arr, index, newItem) => [...arr.slice(0, index), newItem, ...arr.slice(index)];
    const change = (arr, index, newItem) => [...arr.slice(0, index), newItem, ...arr.slice(index).slice(1)];
    const onChangeValue = (event) => {
        var updatedValue = change(value, event.target.name, event.target.value);
        setValue(updatedValue);
        props.onValueChange(props.setting, updatedValue);
    };

    const onClickDelete = (row) => {
        var temp = value;
        if (row > -1) {
            temp.splice(row, 1);
        }
        setValue(temp);
        props.onValueChange(props.setting, temp);
    };
    const onClickAdd = (row) => {
        var temp = value;
        var updatedValue = insert(temp, row + 1, '');
        setValue(updatedValue);
        props.onValueChange(props.setting, updatedValue);
    };

    const generateArray = () => {
        var rows = [];

        rows.push(
            <>
                <IconButton onClick={() => onClickAdd(-1)}>
                    <PlusCircleOutlined />
                </IconButton>
                <br />
                <br />
            </>
        );

        for (let i = 0; i < value.length; i++) {
            rows.push(
                <>
                    <IconButton onClick={() => onClickDelete(i)}>
                        <MinusCircleOutlined />
                    </IconButton>
                    <TextField
                        key={i}
                        id={'fill-' + i}
                        name={i}
                        variant="outlined"
                        onChange={(event) => onChangeValue(event)}
                        style={{ width: '80%' }}
                        value={value[i]}
                    ></TextField>

                    <br />
                    <br />
                </>
            );
        }

        return rows;
    };

    return (
        <div style={{ paddingTop: '10px', paddingLeft: '20px', width: '100%' }}>
            {console.log(value)}
            <Typography style={{ textAlign: 'left', paddingBottom: '5px' }} variant="body1">
                <b>{props.setting.displayName}</b>
            </Typography>
            <Typography style={{ textAlign: 'left' }} variant="body2">
                {props.setting.description}
            </Typography>
            {generateArray()}
        </div>
    );
}
