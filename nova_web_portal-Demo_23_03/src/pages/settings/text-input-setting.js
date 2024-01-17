import { TextField, Typography } from '../../../node_modules/@mui/material/index';
import { useEffect, useState } from 'react';

export default function TextInputSetting(props) {
    const [value, setValue] = useState('');

    useEffect(() => {
        setValue(props.setting.data.value !== undefined ? props.setting.data.value : props.setting.data.defaultValue);
    }, [props.setting.data.value, props.setting.data.defaultValue]);

    const handleInputChange = (e) => {
        setValue(e.target.value);
        props.onValueChange(props.setting, e.target.value);
    };

    return (
        <div style={{ paddingTop: '10px', paddingLeft: '20px', width: '100%' }}>
            <Typography style={{ textAlign: 'left', paddingBottom: '5px' }} variant="body1">
                <b>{props.setting.displayName}</b>
            </Typography>
            <Typography style={{ textAlign: 'left' }} variant="body2">
                {props.setting.description}
            </Typography>
            <TextField
                fullWidth
                required
                id={`${props.setting.type}_${props.setting.name}_value`}
                onChange={handleInputChange}
                value={value || ''}
                style={{ textAlign: 'left', paddingBottom: '20px', paddingRight: '20px' }}
            />
        </div>
    );
}
